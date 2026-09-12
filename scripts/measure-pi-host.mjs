// Sample host and container cgroups without installing monitoring packages.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const label = process.argv[2];
const durationSeconds = Number(process.argv[3]);
if (!label || !Number.isInteger(durationSeconds) || durationSeconds < 5 || durationSeconds > 600) {
  throw new Error('Usage: node scripts/measure-pi-host.mjs LABEL SECONDS (5..600)');
}

const readText = (path) => readFileSync(path, 'utf8').trim();
const command = (name, args) => execFileSync(name, args, { encoding: 'utf8' }).trim();
const percentile = (values, p) => [...values].sort((a, b) => a - b)[Math.ceil(values.length * p) - 1];
const summary = (values) => ({
  median: percentile(values, 0.5),
  p95: percentile(values, 0.95),
  min: Math.min(...values),
  max: Math.max(...values),
});
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

const readHostCpu = () => {
  const values = readText('/proc/stat').split('\n')[0].trim().split(/\s+/).slice(1).map(Number);
  const idle = values[3] + values[4];
  return { idle, total: values.slice(0, 8).reduce((total, value) => total + value, 0) };
};
const readMemory = () => Object.fromEntries(readText('/proc/meminfo').split('\n')
  .map((line) => line.match(/^(\w+):\s+(\d+)/)).filter(Boolean)
  .map((match) => [match[1], Number(match[2]) * 1024]));
const rootSource = command('findmnt', ['-no', 'SOURCE', '/']);
const rootPartition = rootSource.split('/').at(-1);
const rootDevice = command('lsblk', ['-no', 'PKNAME', `/dev/${rootPartition}`]) || rootPartition;
const readDisk = () => {
  const fields = readText('/proc/diskstats').split('\n').map((line) => line.trim().split(/\s+/))
    .find((parts) => parts[2] === rootDevice);
  return { readBytes: Number(fields[5]) * 512, writeBytes: Number(fields[9]) * 512 };
};
const readThermal = () => ({
  temperatureC: Number(readText('/sys/class/thermal/thermal_zone0/temp')) / 1000,
  fanState: Number(readText('/sys/class/thermal/cooling_device0/cur_state')),
});
const readThrottle = () => command('vcgencmd', ['get_throttled']).split('=').at(-1);

const containerCgroups = command('docker', ['ps', '--format', '{{.Names}}']).split('\n').filter(Boolean)
  .map((name) => {
    const pid = command('docker', ['inspect', '--format', '{{.State.Pid}}', name]);
    const relative = readText(`/proc/${pid}/cgroup`).split('\n')
      .find((line) => line.startsWith('0::'))?.slice(3);
    return { name, path: `/sys/fs/cgroup${relative}` };
  });
const readCgroup = ({ name, path }) => {
  try {
    const cpu = Object.fromEntries(readText(`${path}/cpu.stat`).split('\n')
      .map((line) => line.split(' ')).map(([key, value]) => [key, Number(value)]));
    const io = readText(`${path}/io.stat`).split('\n').flatMap((line) => {
      const fields = Object.fromEntries(line.split(' ').slice(1).map((field) => field.split('=')));
      return [{ readBytes: Number(fields.rbytes || 0), writeBytes: Number(fields.wbytes || 0) }];
    }).reduce((total, item) => ({
      readBytes: total.readBytes + item.readBytes,
      writeBytes: total.writeBytes + item.writeBytes,
    }), { readBytes: 0, writeBytes: 0 });
    const memoryBytes = readText(`${path}/cgroup.procs`).split('\n').filter(Boolean)
      .map((pid) => {
        try {
          const match = readText(`/proc/${pid}/status`).match(/^VmRSS:\s+(\d+) kB$/m);
          return match ? Number(match[1]) * 1024 : 0;
        } catch (error) {
          if (error?.code === 'ENOENT') return 0;
          throw error;
        }
      }).reduce((total, bytes) => total + bytes, 0);
    return { name, cpuUsec: cpu.usage_usec, memoryBytes, ...io };
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
};

const startedAt = new Date().toISOString();
const throttleStart = readThrottle();
const host = [];
const containers = Object.fromEntries(containerCgroups.map(({ name }) => [name, []]));
let previousCpu = readHostCpu();
const initialContainers = Object.fromEntries(containerCgroups.flatMap((item) => {
  const sample = readCgroup(item);
  return sample ? [[item.name, sample]] : [];
}));
let previousContainers = structuredClone(initialContainers);
const diskStart = readDisk();
let previousTime = performance.now();
let stopping = false;
process.on('SIGTERM', () => { stopping = true; });
process.on('SIGINT', () => { stopping = true; });
process.send?.('ready');

for (let index = 0; index < durationSeconds; index += 1) {
  await sleep(1000);
  const now = performance.now();
  const elapsedMs = now - previousTime;
  previousTime = now;
  const cpu = readHostCpu();
  const deltaTotal = cpu.total - previousCpu.total;
  const memory = readMemory();
  const thermal = readThermal();
  host.push({
    second: index + 1,
    cpuPercent: 100 * (1 - (cpu.idle - previousCpu.idle) / deltaTotal),
    memoryUsedBytes: memory.MemTotal - memory.MemAvailable,
    swapUsedBytes: memory.SwapTotal - memory.SwapFree,
    load1: Number(readText('/proc/loadavg').split(' ')[0]),
    ...thermal,
  });
  previousCpu = cpu;
  for (const item of containerCgroups) {
    const sample = readCgroup(item);
    const previous = previousContainers[item.name];
    if (!sample || !previous) continue;
    containers[item.name].push({
      second: index + 1,
      cpuCorePercent: (sample.cpuUsec - previous.cpuUsec) / (elapsedMs * 10),
      memoryBytes: sample.memoryBytes,
    });
    previousContainers[item.name] = sample;
  }
  if (stopping) break;
}

const diskEnd = readDisk();
const containerResults = Object.entries(containers).map(([name, samples]) => {
  const first = containerCgroups.find((item) => item.name === name);
  const end = readCgroup(first);
  const start = initialContainers[name];
  if (!start || samples.length === 0) return null;
  return {
    name,
    cpuCorePercent: summary(samples.map((sample) => sample.cpuCorePercent)),
    memoryBytes: summary(samples.map((sample) => sample.memoryBytes)),
    ioDeltaBytes: {
      read: end ? end.readBytes - start.readBytes : null,
      write: end ? end.writeBytes - start.writeBytes : null,
    },
    samples,
  };
}).filter(Boolean);

console.log(JSON.stringify({
  label,
  startedAt,
  finishedAt: new Date().toISOString(),
  requestedDurationSeconds: durationSeconds,
  durationSeconds: (Date.now() - Date.parse(startedAt)) / 1000,
  sampleIntervalMs: 1000,
  containerMemoryMetric: 'sum_process_rss_bytes',
  rootDevice,
  throttleStart,
  throttleEnd: readThrottle(),
  diskDeltaBytes: {
    read: diskEnd.readBytes - diskStart.readBytes,
    write: diskEnd.writeBytes - diskStart.writeBytes,
  },
  hostSummary: {
    cpuPercent: summary(host.map((sample) => sample.cpuPercent)),
    memoryUsedBytes: summary(host.map((sample) => sample.memoryUsedBytes)),
    load1: summary(host.map((sample) => sample.load1)),
    temperatureC: summary(host.map((sample) => sample.temperatureC)),
    fanState: summary(host.map((sample) => sample.fanState)),
    swapUsedBytes: summary(host.map((sample) => sample.swapUsedBytes)),
  },
  hostSamples: host,
  containers: containerResults,
}, null, 2));
