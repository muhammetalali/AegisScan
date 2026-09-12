#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import math
import statistics
import time
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass
class Sample:
    path: str
    status: int
    latency_ms: float
    ok: bool


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered=sorted(values)
    rank=(len(ordered)-1)*q
    low=math.floor(rank); high=math.ceil(rank)
    if low==high:
        return ordered[low]
    return ordered[low]*(high-rank)+ordered[high]*(rank-low)


async def run_stage(
    base_url: str,
    paths: list[str],
    concurrency: int,
    duration: float,
    request_timeout: float,
    warmup_seconds: float = 2.0,
) -> dict:
    samples: list[Sample]=[]
    warmup_requests=0
    lock=asyncio.Lock()
    stage_started=time.monotonic()
    measure_at=stage_started+warmup_seconds
    stop_at=measure_at+duration

    async with httpx.AsyncClient(base_url=base_url,timeout=request_timeout,limits=httpx.Limits(max_connections=concurrency,max_keepalive_connections=concurrency)) as client:
        async def worker(worker_id: int):
            nonlocal warmup_requests
            local: list[Sample]=[]
            local_warmup=0
            index=worker_id
            while time.monotonic()<stop_at:
                path=paths[index%len(paths)]
                index+=1
                request_started=time.monotonic()
                perf_started=time.perf_counter()
                status=0; ok=False
                try:
                    response=await client.get(path)
                    status=response.status_code
                    ok=200 <= status < 300
                except httpx.HTTPError:
                    pass
                latency_ms=(time.perf_counter()-perf_started)*1000.0
                if request_started >= measure_at:
                    local.append(Sample(path,status,latency_ms,ok))
                else:
                    local_warmup+=1
            async with lock:
                samples.extend(local)
                warmup_requests+=local_warmup

        await asyncio.gather(*(worker(i) for i in range(concurrency)))
        elapsed=max(0.001,time.monotonic()-measure_at)

    latencies=[sample.latency_ms for sample in samples]
    failures=sum(1 for sample in samples if not sample.ok)
    status_counts={}
    for sample in samples:
        key=str(sample.status)
        status_counts[key]=status_counts.get(key,0)+1

    per_path={}
    for path in paths:
        path_samples=[sample for sample in samples if sample.path==path]
        path_latencies=[sample.latency_ms for sample in path_samples]
        path_failures=sum(1 for sample in path_samples if not sample.ok)
        per_path[path]={
            'requests':len(path_samples),
            'failures':path_failures,
            'error_rate':round(path_failures/max(1,len(path_samples)),6),
            'throughput_rps':round(len(path_samples)/elapsed,3),
            'latency_ms':{
                'min':round(min(path_latencies),3) if path_latencies else 0,
                'mean':round(statistics.fmean(path_latencies),3) if path_latencies else 0,
                'p50':round(percentile(path_latencies,0.50),3),
                'p95':round(percentile(path_latencies,0.95),3),
                'p99':round(percentile(path_latencies,0.99),3),
                'max':round(max(path_latencies),3) if path_latencies else 0,
            },
        }
    return {
        'concurrency':concurrency,
        'warmup_seconds':round(warmup_seconds,3),
        'warmup_requests':warmup_requests,
        'duration_seconds':round(elapsed,3),
        'requests':len(samples),
        'failures':failures,
        'error_rate':round(failures/max(1,len(samples)),6),
        'throughput_rps':round(len(samples)/elapsed,3),
        'latency_ms':{
            'min':round(min(latencies),3) if latencies else 0,
            'mean':round(statistics.fmean(latencies),3) if latencies else 0,
            'p50':round(percentile(latencies,0.50),3),
            'p95':round(percentile(latencies,0.95),3),
            'p99':round(percentile(latencies,0.99),3),
            'max':round(max(latencies),3) if latencies else 0,
        },
        'per_path':per_path,
        'status_counts':status_counts,
    }


async def main_async(args) -> int:
    stages=[]
    for item in args.stage:
        concurrency_text,duration_text=item.split(':',1)
        concurrency=int(concurrency_text); duration=float(duration_text)
        if not 1<=concurrency<=1000 or not 1<=duration<=3600:
            raise ValueError('stage must be CONCURRENCY:DURATION with safe positive bounds')
        stages.append(await run_stage(
            args.base_url,
            args.path,
            concurrency,
            duration,
            args.request_timeout,
            args.stage_warmup_seconds,
        ))

    requests=sum(stage['requests'] for stage in stages)
    failures=sum(stage['failures'] for stage in stages)
    p95=max((stage['latency_ms']['p95'] for stage in stages),default=0)
    minimum_rps=min((stage['throughput_rps'] for stage in stages),default=0)
    error_rate=failures/max(1,requests)
    passed=requests>=args.min_requests and error_rate<=args.max_error_rate and p95<=args.max_p95_ms and minimum_rps>=args.min_rps
    report={
        'schema':'aegisscan.performance-reality.v1',
        'base_url':args.base_url,
        'paths':args.path,
        'stages':stages,
        'summary':{
            'requests':requests,'failures':failures,'error_rate':round(error_rate,6),
            'worst_stage_p95_ms':round(p95,3),'minimum_stage_rps':round(minimum_rps,3),
        },
        'thresholds':{
            'min_requests':args.min_requests,'max_error_rate':args.max_error_rate,
            'max_p95_ms':args.max_p95_ms,'min_rps':args.min_rps,
            'stage_warmup_seconds':args.stage_warmup_seconds,
        },
        'passed':passed,
    }
    rendered=json.dumps(report,indent=2,sort_keys=True)
    print(rendered)
    Path(args.output).write_text(rendered+'\n',encoding='utf-8')
    return 0 if passed else 1


def parse_args():
    parser=argparse.ArgumentParser()
    parser.add_argument('--base-url',required=True)
    parser.add_argument('--path',action='append',default=[])
    parser.add_argument('--stage',action='append',default=[])
    parser.add_argument('--request-timeout',type=float,default=5.0)
    parser.add_argument('--stage-warmup-seconds',type=float,default=2.0)
    parser.add_argument('--max-p95-ms',type=float,default=500.0)
    parser.add_argument('--max-error-rate',type=float,default=0.01)
    parser.add_argument('--min-rps',type=float,default=5.0)
    parser.add_argument('--min-requests',type=int,default=100)
    parser.add_argument('--output',default='performance-reality.json')
    args=parser.parse_args()
    if not args.path:
        args.path=['/health','/ready']
    if not args.stage:
        args.stage=['10:15','30:20','60:20','25:90']
    if not 0 <= args.stage_warmup_seconds <= 60:
        parser.error('--stage-warmup-seconds must be between 0 and 60')
    return args


if __name__=='__main__':
    raise SystemExit(asyncio.run(main_async(parse_args())))
