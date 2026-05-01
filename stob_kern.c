#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

/* Redefine basic types to avoid header conflicts */
typedef __u64 u64;
typedef __u32 u32;

SEC("classifier")
int stob_defense(struct __sk_buff *skb) {
    /* 
     * Stob Timing Primitive: Inter-arrival Jitter (Section 4.2)
     *
     * We modify the packet's departure timestamp (tstamp). 
     * When the FQ (Fair Queuing) qdisc sees this, it will hold the packet
     * until that exact time. This destroys the 'inter-arrival time' 
     * features that the Random Forest model uses to identify sites.
     */
    
    u64 now = bpf_ktime_get_ns();
    
    /* 
     * We add a base delay of 5ms (5,000,000 ns) 
     * plus a random jitter of 0-5ms (0-5,000,000 ns).
     * This creates a 'Regularized' but noisy timing pattern.
     */
    u32 jitter = bpf_get_prandom_u32() % 5000000; 
    u64 delay = 5000000 + (u64)jitter; 
    
    skb->tstamp = now + delay;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";