import Darwin

func monotonicTestTime() -> UInt64 {
    var value = timespec()
    precondition(clock_gettime(CLOCK_MONOTONIC_RAW, &value) == 0)
    return UInt64(value.tv_sec) * 1_000_000_000 + UInt64(value.tv_nsec)
}

func monotonicTestElapsed(since start: UInt64) -> UInt64 {
    monotonicTestTime() - start
}
