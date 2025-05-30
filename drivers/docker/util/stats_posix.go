// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package util

import (
	containerapi "github.com/docker/docker/api/types/container"
	"github.com/hashicorp/nomad/client/lib/cpustats"
	cstructs "github.com/hashicorp/nomad/client/structs"
)

var (
	DockerMeasuredCPUStats = []string{"Throttled Periods", "Throttled Time", "Percent"}

	// cgroup-v2 only exposes a subset of memory stats
	DockerCgroupV1MeasuredMemStats = []string{"RSS", "Cache", "Swap", "Usage", "Max Usage"}
	DockerCgroupV2MeasuredMemStats = []string{"RSS", "Cache", "Swap", "Usage"}
)

func DockerStatsToTaskResourceUsage(s *containerapi.StatsResponse, compute cpustats.Compute) *cstructs.TaskResourceUsage {
	var (
		totalCompute = compute.TotalCompute
		totalCores   = compute.NumCores
	)

	measuredMems := DockerCgroupV1MeasuredMemStats

	// use a simple heuristic to check if cgroup-v2 is used.
	// go-dockerclient doesn't distinguish between 0 and not-present value
	if s.MemoryStats.MaxUsage == 0 && s.MemoryStats.Usage != 0 {
		measuredMems = DockerCgroupV2MeasuredMemStats
	}

	cache := s.MemoryStats.Stats["cache"]
	if cache == 0 {
		// This is the equivalent stat for cgroups v2, including filesystem
		// cache and tmpfs
		cache = s.MemoryStats.Stats["file"]
	}
	rss := s.MemoryStats.Stats["rss"]
	if rss == 0 {
		// This is the equivalent stat of anonymous mappings for cgroups v2.
		rss = s.MemoryStats.Stats["anon"]
	}

	// containerapi exposes memory stat file as a map. for the meaning of the
	// source values, consult:
	// https://www.kernel.org/doc/Documentation/cgroup-v1/memory.txt
	// https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files
	ms := &cstructs.MemoryStats{
		MappedFile: s.MemoryStats.Stats["file_mapped"],
		Cache:      cache,
		RSS:        rss,
		Swap:       s.MemoryStats.Stats["swap"],
		Usage:      s.MemoryStats.Usage,
		MaxUsage:   s.MemoryStats.MaxUsage,
		Measured:   measuredMems,
	}

	cs := &cstructs.CpuStats{
		ThrottledPeriods: s.CPUStats.ThrottlingData.ThrottledPeriods,
		ThrottledTime:    s.CPUStats.ThrottlingData.ThrottledTime,
		Measured:         DockerMeasuredCPUStats,
	}

	// Calculate percentage
	cs.Percent = CalculateCPUPercent(
		s.CPUStats.CPUUsage.TotalUsage, s.PreCPUStats.CPUUsage.TotalUsage,
		s.CPUStats.SystemUsage, s.PreCPUStats.SystemUsage, totalCores)
	cs.SystemMode = CalculateCPUPercent(
		s.CPUStats.CPUUsage.UsageInKernelmode, s.PreCPUStats.CPUUsage.UsageInKernelmode,
		s.CPUStats.CPUUsage.TotalUsage, s.PreCPUStats.CPUUsage.TotalUsage, totalCores)
	cs.UserMode = CalculateCPUPercent(
		s.CPUStats.CPUUsage.UsageInUsermode, s.PreCPUStats.CPUUsage.UsageInUsermode,
		s.CPUStats.CPUUsage.TotalUsage, s.PreCPUStats.CPUUsage.TotalUsage, totalCores)

	cs.TotalTicks = (cs.Percent / 100) * float64(totalCompute) / float64(totalCores)

	return &cstructs.TaskResourceUsage{
		ResourceUsage: &cstructs.ResourceUsage{
			MemoryStats: ms,
			CpuStats:    cs,
		},
		Timestamp: s.Read.UTC().UnixNano(),
	}
}
