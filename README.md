# cachecontroller

A Linux kernel module to dynamically disable/enable CPU caches per core via sysfs.

## Usage

The module creates `/sys/kernel/cache_disable/cpuX/cache_disable` for each CPU `X`.

*   **Disable Cache for CPU X:**
    ```bash
    echo 1 | sudo tee /sys/kernel/cache_disable/cpuX/cache_disable
    ```
*   **Enable Cache for CPU X:**
    ```bash
    echo 0 | sudo tee /sys/kernel/cache_disable/cpuX/cache_disable
    ```
*   **Disable Cache for All CPUs:**
    ```bash
    for cpu in $(seq 0 $(($(nproc) - 1))); do 
        echo 1 | sudo tee "/sys/kernel/cache_disable/cpu${cpu}/cache_disable"
    done
    ```

## Mechanism

Disabling sets the `CD` (Cache Disable) bit and clears the `NW` (Not Write-through) bit in the `CR0` control register, then executes `wbinvd` to invalidate caches. Re-enabling clears these bits.

## Build & Load

1.  **Build:** `make` (Requires kernel headers)
2.  **Load:** `sudo insmod cachecontroller.ko`
3.  **Unload:** `sudo rmmod cachecontroller`