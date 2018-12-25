#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static unsigned int kportal_http_redirect(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int ret;
	const struct iphdr *iph;
	const struct tcphdr *th;

	ret = NF_ACCEPT;
	iph = ip_hdr(skb);//取报文ip头
	if(iph->protocol != IPPROTO_TCP)
	{
		goto OUT;
	}

	if (!pskb_may_pull(skb, (4 * iph->ihl) + sizeof(struct tcphdr))) {
		//报文长度不足tcp头长度，跳出
		goto OUT;
	}

	th = (const struct tcphdr *)(((char*)iph)+(4*iph->ihl));

	if (unlikely(th->doff < sizeof(struct tcphdr) / 4))
	{
		//tcp头部过小(不足不含选项头大小）
		goto OUT;
	}

#if 0
	if (!pskb_may_pull(skb, th->doff * 4))
	{
		//报文长度不足tcp头长度（含选项）
		goto OUT;
	}
#endif

	if(th->dest != cpu_to_be16(80))
	{
		//TODO XXX 需要考虑源ip限制
		//TODO 确认为出接口报文时上送
		goto OUT;
	}

	//查询连接跟踪，将new状态上送

	//如果非new状态，读取扩展内容，检查其结果，如果直通，则将其pass
	//如果非直通，将其上送给对端

	//对目标ip做nat,通过kni口送上去，
	printk(KERN_INFO "kportal rcv http packet!\n");
	OUT:{
		return ret;
	}
}

static const struct nf_hook_ops kportal_ops[] = {
	{
		.hook =kportal_http_redirect,
		.pf = NFPROTO_IPV4,
		.hooknum =NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_LAST - 1,
	}
};

static inline int kportal_register_net_hooks(void)
{
	struct net *net;
	net = &init_net;
	return nf_register_net_hooks(net, kportal_ops,
			ARRAY_SIZE(kportal_ops));
}

static inline void kportal_unregister_net_hooks(void)
{
	struct net *net;
	net = &init_net;
	nf_unregister_net_hooks(net,kportal_ops,ARRAY_SIZE(kportal_ops));
}

static int kportal_init(void)
{
	printk(KERN_INFO "kportal init ok!\n");

	if (kportal_register_net_hooks()) {
		printk("kportal register net hooks failed.\n");
		return -1;
	}
	return 0;
}

static void kportal_exit(void)
{
	kportal_unregister_net_hooks();
}

module_init(kportal_init);
module_exit(kportal_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("anlaneg@126.com");
MODULE_DESCRIPTION("support portal");
MODULE_VERSION("0.0.1");
