#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>
#include <asm/segment.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <net/genetlink.h>

enum {
  KSEC_A_UNSPEC,
  KSEC_A_STR,
  KSEC_A_U64_0,
  KSEC_A_U64_1,
  KSEC_A_U64_2,
  KSEC_A_BIN_0,
  KSEC_A_BIN_1,
  KSEC_A_BIN_2,
  KSEC_A_BIN_3,
  __KSEC_A_MAX,
};
#define KSEC_A_MAX (__KSEC_A_MAX - 1)

enum {
  KSEC_C_UNSPEC,
  KSEC_C_IS_KERNEL_ADDR,
  KSEC_C_IS_MODULE_ADDR,
  KSEC_C_GET_IDT_ENTRIES,
  KSEC_C_GET_SYSCALLS,
  KSEC_C_GET_MODULES,
  KSEC_C_GET_SYMBOL_ADDR,
  KSEC_C_READ,
  KSEC_C_ALLOC_EXEC_MEM,
  KSEC_C_HOOK,
  KSEC_C_GET_SHIM_ADDR,
  KSEC_C_KPROBE,
  __KSEC_C_MAX,
};
#define KSEC_C_MAX (__KSEC_C_MAX - 1)

static struct nla_policy ksec_genl_policy[KSEC_A_MAX + 1] = {
  [KSEC_A_STR] = { .type = NLA_NUL_STRING },
  [KSEC_A_U64_0] = { .type = NLA_U64 },
  [KSEC_A_U64_1] = { .type = NLA_U64 },
  [KSEC_A_U64_2] = { .type = NLA_U64 },
  [KSEC_A_BIN_0] = { .type = NLA_BINARY },
  [KSEC_A_BIN_1] = { .type = NLA_BINARY },
  [KSEC_A_BIN_2] = { .type = NLA_BINARY },
  [KSEC_A_BIN_3] = { .type = NLA_BINARY },
};

static int get_idt_entries(struct sk_buff *, struct genl_info *);
static int get_syscalls(struct sk_buff *, struct genl_info *);
static int get_modules(struct sk_buff *, struct genl_info *);
static int get_symbol_addr(struct sk_buff *, struct genl_info *);
static int read(struct sk_buff *, struct genl_info *);
static int alloc_exec_mem(struct sk_buff *, struct genl_info *);
static int hook(struct sk_buff *, struct genl_info *);
static int kprobe(struct sk_buff *, struct genl_info *);
static int get_shim_addr(struct sk_buff *, struct genl_info *);
static int is_kernel_addr(struct sk_buff *, struct genl_info *);
static int is_module_addr(struct sk_buff *, struct genl_info *);

static struct genl_ops ksec_ops[] = {
  {
    .cmd = KSEC_C_GET_IDT_ENTRIES,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = get_idt_entries,
  },
  {
    .cmd = KSEC_C_IS_KERNEL_ADDR,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = is_kernel_addr,
  },
  {
    .cmd = KSEC_C_IS_MODULE_ADDR,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = is_module_addr,
  },
  {
    .cmd = KSEC_C_GET_SYSCALLS,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = get_syscalls,
  },
  {
    .cmd = KSEC_C_GET_MODULES,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = get_modules,
  },
  {
    .cmd = KSEC_C_GET_SYMBOL_ADDR,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = get_symbol_addr,
  },
  {
    .cmd = KSEC_C_READ,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = read,
  },
  {
    .cmd = KSEC_C_ALLOC_EXEC_MEM,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = alloc_exec_mem,
  },
  {
    .cmd = KSEC_C_HOOK,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = hook,
  },
  {
    .cmd = KSEC_C_GET_SHIM_ADDR,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = get_shim_addr,
  },
  {
    .cmd = KSEC_C_KPROBE,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = kprobe,
  },
};

static struct genl_family ksec_genl_family = {
  .id = 0x0,
  .hdrsize = 0,
  .name = "ksec",
  .version = 1,
  .maxattr = KSEC_A_MAX,
  .ops = ksec_ops,
  .n_ops = 11,
};

typedef void *(*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t lookup;

static int is_kernel_addr(struct sk_buff *skb, struct genl_info *info) {
  int (*core_kernel_text)(unsigned long addr) = lookup("core_kernel_text");

  u64 va = nla_get_u64(info->attrs[KSEC_A_U64_0]);
  u64 res = core_kernel_text(va);

  struct sk_buff *reply_skb = genlmsg_new(sizeof(u64), GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_IS_KERNEL_ADDR);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put_u64_64bit(reply_skb, KSEC_A_U64_0, res, 0);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static int is_module_addr(struct sk_buff *skb, struct genl_info *info) {
  struct module *(*get_module_from_addr)(unsigned long addr) = lookup("__module_address");

  u64 va = nla_get_u64(info->attrs[KSEC_A_U64_0]);
  struct module *module = get_module_from_addr(va);

  char *module_name;
  if (module) module_name = module->name;
  else module_name = "";

  struct sk_buff *reply_skb = genlmsg_new(sizeof(module_name), GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_IS_MODULE_ADDR);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put_string(reply_skb, KSEC_A_STR, module_name);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static int get_idt_entries(struct sk_buff *skb, struct genl_info *info) {
  unsigned __int128 *idt_table = (unsigned __int128 *)lookup("idt_table");

  struct sk_buff *reply_skb = genlmsg_new(sizeof(unsigned __int128) * IDT_ENTRIES, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_GET_IDT_ENTRIES);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put(reply_skb, KSEC_A_BIN_0, sizeof(unsigned __int128) * IDT_ENTRIES, idt_table);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static int get_syscalls(struct sk_buff *skb, struct genl_info *info) {
  sys_call_ptr_t *sys_call_table = lookup("sys_call_table");

  struct sk_buff *reply_skb = genlmsg_new(sizeof(sys_call_ptr_t) * NR_syscalls, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_GET_SYSCALLS);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put(reply_skb, KSEC_A_BIN_0, sizeof(sys_call_ptr_t) * NR_syscalls, sys_call_table);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static int get_modules(struct sk_buff *skb, struct genl_info *info) {
  struct kset *mod_kset = lookup("module_kset");
  struct kobject *cur, *tmp;
  char *buf = kzalloc(32000, GFP_KERNEL);
  unsigned int buf_p = 0;

  list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry) {
    if (!kobject_name(tmp))
      break;

    struct module_kobject *kobj = container_of(tmp, struct module_kobject, kobj);

    if (kobj && kobj->mod) {
      strcat(buf + buf_p, kobj->mod->name);
      strcat(buf, " ");
      buf_p += strlen(kobj->mod->name) + 1;
    }
  }

  struct sk_buff *reply_skb = genlmsg_new(buf_p, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_GET_MODULES);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put(reply_skb, KSEC_A_BIN_0, buf_p, buf);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static int get_symbol_addr(struct sk_buff *skb, struct genl_info *info) {
  char *name = nla_data(info->attrs[KSEC_A_STR]);

  u64 addr = (u64)lookup(name);

  struct sk_buff *reply_skb = genlmsg_new(sizeof(u64), GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_GET_SYMBOL_ADDR);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put_u64_64bit(reply_skb, KSEC_A_U64_0, addr, 0);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static int read(struct sk_buff *skb, struct genl_info *info) {
  char *va_str = nla_data(info->attrs[KSEC_A_STR]);
  u64 va;
  int e = kstrtoull(va_str, 16, &va);
  if (e != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return e;
  }
  u64 len = nla_get_u64(info->attrs[KSEC_A_U64_0]);

  struct sk_buff *reply_skb = genlmsg_new(len, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_READ);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put(reply_skb, KSEC_A_BIN_0, len, (void *)va);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static int alloc_exec_mem(struct sk_buff *skb, struct genl_info *info) {
  void *(*__vmalloc_node_range)(unsigned long size, unsigned long align, unsigned long start, unsigned long end, gfp_t gfp_mask, pgprot_t prot, unsigned long vm_flags, int node, const void *caller) = lookup("__vmalloc_node_range");

  u64 addr = (u64)__vmalloc_node_range(2048, 1, VMALLOC_START, VMALLOC_END, GFP_KERNEL, PAGE_KERNEL_EXEC, VM_FLUSH_RESET_PERMS, NUMA_NO_NODE, __builtin_return_address(0));

  struct sk_buff *reply_skb = genlmsg_new(sizeof(u64), GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_ALLOC_EXEC_MEM);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put_u64_64bit(reply_skb, KSEC_A_U64_0, addr, 0);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static void write_cr0_unsafe(unsigned long val) {
  asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
}

static void shim(void) {
  printk("Inside shim\n");
}

static int hook(struct sk_buff *skb, struct genl_info *info) {
  u64 exec_addr = nla_get_u64(info->attrs[KSEC_A_U64_0]);
  u64 hook_addr = nla_get_u64(info->attrs[KSEC_A_U64_1]);
  u64 hook_insns_len = nla_get_u64(info->attrs[KSEC_A_U64_2]);
  void *hook_insns = nla_data(info->attrs[KSEC_A_BIN_0]);
  void *replaced_insns = nla_data(info->attrs[KSEC_A_BIN_1]);
  void *jmp_back_insns = nla_data(info->attrs[KSEC_A_BIN_2]);
  void *shim_insns = nla_data(info->attrs[KSEC_A_BIN_3]);

  unsigned long old_cr0 = read_cr0();
  write_cr0_unsafe(old_cr0 & ~(X86_CR0_WP));
  memcpy((void *)hook_addr, hook_insns, hook_insns_len);
  write_cr0_unsafe(old_cr0);

  memcpy((void *)exec_addr, shim_insns, 13);
  memcpy((char *)exec_addr + 13, replaced_insns, hook_insns_len);
  memcpy((char *)exec_addr + 13 + hook_insns_len, jmp_back_insns, 13);

  struct sk_buff *reply_skb = genlmsg_new(sizeof(u64), GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_HOOK);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put_u64_64bit(reply_skb, KSEC_A_U64_0, 1, 0);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static int get_shim_addr(struct sk_buff *skb, struct genl_info *info) {
  char *hooked = nla_data(info->attrs[KSEC_A_STR]);
  u64 addr;

  //if (strcmp(hooked, "netif_rx") == 0) addr = (u64)&consume_sk_buff;
  addr = (u64)&shim;

  struct sk_buff *reply_skb = genlmsg_new(sizeof(u64), GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_GET_SHIM_ADDR);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put_u64_64bit(reply_skb, KSEC_A_U64_0, addr, 0);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

static int __kprobes kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs) {
  pr_info("%lx\n", regs->di);
  return 0;
}

static int kprobe(struct sk_buff *skb, struct genl_info *info) {
  char *hooked = nla_data(info->attrs[KSEC_A_STR]);
  struct kprobe kp = {
    .symbol_name = hooked,
  };

  kp.pre_handler = kprobe_pre_handler;
  u64 ret = register_kprobe(&kp);

  if (ret < 0) pr_err("register_kprobe failed, returned %d\n", ret);

  struct sk_buff *reply_skb = genlmsg_new(sizeof(u64), GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_KPROBE);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put_u64_64bit(reply_skb, KSEC_A_U64_0, ret, 0);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);
  if (rc != 0) {
    pr_err("An error occurred in %s()\n", __func__);
    return -rc;
  }

  return 0;
}

void resolve_kallsyms_lookup_name(void) {
  static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
  };
  register_kprobe(&kp);
  lookup = (kallsyms_lookup_name_t)kp.addr;
  unregister_kprobe(&kp);
}

static int __init modinit(void) {
  int rc = genl_register_family(&ksec_genl_family);
  if (rc != 0) {
    pr_err("%s\n", "Couldn't register generic netlink family");
    return 1;
  }

  resolve_kallsyms_lookup_name();

  return 0;
}

static void __exit modexit(void) {
  int rc = genl_unregister_family(&ksec_genl_family);
  if (rc !=0) pr_err("%s\n", "Failed to unregister netlink family");
}

module_init(modinit);
module_exit(modexit);
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0");
