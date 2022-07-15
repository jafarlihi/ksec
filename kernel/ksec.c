#include "asm/segment.h"
#include "linux/gfp.h"
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <net/genetlink.h>

enum {
  KSEC_A_UNSPEC,
  KSEC_A_STR,
  KSEC_A_BIN,
  KSEC_A_U64,
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
  __KSEC_C_MAX,
};
#define KSEC_C_MAX (__KSEC_C_MAX - 1)

static struct nla_policy ksec_genl_policy[KSEC_A_MAX + 1] = {
  [KSEC_A_STR] = { .type = NLA_NUL_STRING },
  [KSEC_A_BIN] = { .type = NLA_BINARY },
  [KSEC_A_U64] = { .type = NLA_U64 },
};

static int get_idt_entries(struct sk_buff *, struct genl_info *);
static int get_syscalls(struct sk_buff *, struct genl_info *);
static int get_modules(struct sk_buff *, struct genl_info *);
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
};

static struct genl_family ksec_genl_family = {
  .id = 0x0,
  .hdrsize = 0,
  .name = "ksec",
  .version = 1,
  .maxattr = KSEC_A_MAX,
  .ops = ksec_ops,
  .n_ops = 5,
};

typedef void *(*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t lookup;

static int is_kernel_addr(struct sk_buff *skb, struct genl_info *info) {
  int (*core_kernel_text)(unsigned long addr) = lookup("core_kernel_text");

  u64 va = nla_get_u64(info->attrs[KSEC_A_U64]);
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

  int rc = nla_put_u64_64bit(reply_skb, KSEC_A_U64, res, 0);
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

  u64 va = nla_get_u64(info->attrs[KSEC_A_U64]);
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

  int rc = nla_put(reply_skb, KSEC_A_BIN, sizeof(unsigned __int128) * IDT_ENTRIES, idt_table);
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

  int rc = nla_put(reply_skb, KSEC_A_BIN, sizeof(sys_call_ptr_t) * NR_syscalls, sys_call_table);
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

  int rc = nla_put(reply_skb, KSEC_A_BIN, buf_p, buf);
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
  lookup = (kallsyms_lookup_name_t) kp.addr;
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
