// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <asm/cpu_device_id.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>

// Per-CPU data structure to track cache disable state
struct per_cpu_cache_disable {
    bool is_disabled;
    struct kobject *kobj;
};

// Global array to store per-cpu cache disable information
static struct per_cpu_cache_disable __percpu *cache_disable_info;

// Global kobject for the module
static struct kobject *cache_disable_kobj;

// Function to disable/enable caches for a specific CPU
static void toggle_cpu_cache(void *info) {
    struct per_cpu_cache_disable *pcpu_info =
        (struct per_cpu_cache_disable *)info;
    unsigned long cr0;

    // Read current CR0 value
    cr0 = read_cr0();

    if (pcpu_info->is_disabled) {
        // Disable cache
        cr0 |= X86_CR0_CD;  // Set Cache Disable bit
        cr0 &= ~X86_CR0_NW; // Clear Not Write-through bit
    } else {
        // Re-enable cache
        cr0 &= ~X86_CR0_CD; // Clear Cache Disable bit
        cr0 &= ~X86_CR0_NW; // Ensure Not Write-through is clear
    }

    // Write back modified CR0
    write_cr0(cr0);

    // Flush caches
    wbinvd();
}

// Sysfs show function to display current cache state
static ssize_t cache_disable_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf) {
    int cpu = kobj->state_initialized;
    struct per_cpu_cache_disable *pcpu_info;

    pcpu_info = per_cpu_ptr(cache_disable_info, cpu);
    return sprintf(buf, "%d\n", pcpu_info->is_disabled);
}

// Sysfs store function to change cache state
static ssize_t cache_disable_store(struct kobject *kobj,
                                   struct kobj_attribute *attr, const char *buf,
                                   size_t count) {
    int cpu = kobj->state_initialized;
    struct per_cpu_cache_disable *pcpu_info;
    bool new_state;
    int ret;

    // Parse input
    ret = kstrtobool(buf, &new_state);
    if (ret < 0) return ret;

    // Get per-cpu info
    pcpu_info = per_cpu_ptr(cache_disable_info, cpu);

    // Only change if state is different
    if (pcpu_info->is_disabled != new_state) {
        pcpu_info->is_disabled = new_state;

        // Run on the specific CPU
        smp_call_function_single(cpu, toggle_cpu_cache, pcpu_info, 1);
    }

    return count;
}

// Define the sysfs attribute
static struct kobj_attribute cache_disable_attr =
    __ATTR(cache_disable, 0644, cache_disable_show, cache_disable_store);

// Callback for CPU online event
static int cache_disable_cpu_online(unsigned int cpu) {
    struct per_cpu_cache_disable *pcpu_info;
    char name[20];
    int ret;

    // Get per-cpu info
    pcpu_info = per_cpu_ptr(cache_disable_info, cpu);

    // Create a kobject for this specific CPU
    snprintf(name, sizeof(name), "cpu%d", cpu);

    pcpu_info->kobj = kobject_create_and_add(name, cache_disable_kobj);
    if (!pcpu_info->kobj) {
        pr_err("Failed to create kobject for CPU %d\n", cpu);
        return -ENOMEM;
    }

    // Create sysfs file
    ret = sysfs_create_file(pcpu_info->kobj, &cache_disable_attr.attr);
    if (ret) {
        pr_err("Failed to create sysfs file for CPU %d\n", cpu);
        kobject_put(pcpu_info->kobj);
        pcpu_info->kobj = NULL;
        return ret;
    }

    return 0;
}

// Callback for CPU offline event
static int cache_disable_cpu_offline(unsigned int cpu) {
    struct per_cpu_cache_disable *pcpu_info;

    // Get per-cpu info
    pcpu_info = per_cpu_ptr(cache_disable_info, cpu);

    // Remove sysfs file if it exists
    if (pcpu_info->kobj) {
        sysfs_remove_file(pcpu_info->kobj, &cache_disable_attr.attr);
        kobject_put(pcpu_info->kobj);
        pcpu_info->kobj = NULL;
    }

    return 0;
}

// Module initialization
static int __init cache_disable_init(void) {
    int ret;

    // Create a kobject for the module under /sys/kernel
    cache_disable_kobj = kobject_create_and_add("cache_disable", kernel_kobj);
    if (!cache_disable_kobj) {
        pr_err("Failed to create cache_disable kobject\n");
        return -ENOMEM;
    }

    // Allocate per-cpu data
    cache_disable_info = alloc_percpu(struct per_cpu_cache_disable);
    if (!cache_disable_info) {
        kobject_put(cache_disable_kobj);
        return -ENOMEM;
    }

    // Register CPU hotplug callbacks
    ret =
        cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "cache_disable",
                          cache_disable_cpu_online, cache_disable_cpu_offline);
    if (ret < 0) {
        pr_err("Failed to register CPU hotplug callbacks\n");
        free_percpu(cache_disable_info);
        kobject_put(cache_disable_kobj);
        return ret;
    }

    pr_info("cachecontroller oaded\n");
    return 0;
}

// Module cleanup
static void __exit cache_disable_exit(void) {
    // Unregister CPU hotplug callbacks
    cpuhp_remove_state_nocalls(CPUHP_AP_ONLINE_DYN);

    // Free per-cpu data
    free_percpu(cache_disable_info);

    // Remove the module's kobject
    kobject_put(cache_disable_kobj);

    pr_info("cachecontroller unloaded\n");
}

module_init(cache_disable_init);
module_exit(cache_disable_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("James Young");
MODULE_DESCRIPTION("cachecontroller is a linux kernel module to disable the "
                   "cache on a running system ");
MODULE_VERSION("0.1");
