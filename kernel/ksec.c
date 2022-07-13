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
  KSEC_A_MSG,
  KSEC_A_U8,
  KSEC_A_BIN,
  __KSEC_A_MAX,
};
#define KSEC_A_MAX (__KSEC_A_MAX - 1)

enum {
  KSEC_C_UNSPEC,
  KSEC_C_GET_IDT_ENTRIES,
  __KSEC_C_MAX,
};
#define KSEC_C_MAX (__KSEC_C_MAX - 1)

static struct nla_policy ksec_genl_policy[KSEC_A_MAX + 1] = {
  [KSEC_A_MSG] = { .type = NLA_NUL_STRING },
  [KSEC_A_U8] = { .type = NLA_U8 },
  [KSEC_A_BIN] = { .type = NLA_BINARY },
};

static int get_idt_entries(struct sk_buff *, struct genl_info *);

static struct genl_ops ksec_ops[] = {
  {
    .cmd = KSEC_C_GET_IDT_ENTRIES,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = get_idt_entries,
  },
};

static struct genl_family ksec_genl_family = {
  .id = 0x0,
  .hdrsize = 0,
  .name = "ksec",
  .version = 1,
  .maxattr = KSEC_A_MAX,
  .ops = ksec_ops,
  .n_ops = 1,
};

typedef void *(*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t lookup;
static unsigned __int128 *idt_table = NULL;

typedef struct {
  u16 offset_0_15;
  u16 selector;
  struct access_byte {
    u8 ist : 2;
    u8 reserved : 4;
    u8 gate_type : 3;
    u8 zero : 1;
    u8 dpl : 1;
    u8 p : 1;
  } ab;
  u16 offset_16_31;
  u32 offset_32_63;
  u32 reserved;
} __attribute__((packed)) idt_entry_t;

typedef union {
  unsigned __int128 scalar;
  idt_entry_t structure;
} idt_entry_u_t;

#define N_IDT 1024

idt_entry_u_t idt_entry_info_arr[N_IDT] = {0};

static int get_idt_entries(struct sk_buff *skb, struct genl_info *info) {
  for (int i = 0; i < IDT_ENTRIES; i++) {
    idt_entry_u_t entry;
    entry.scalar = idt_table[i];
    idt_entry_info_arr[i] = entry;
  }

  u8 *to_send = kmalloc(sizeof(idt_entry_u_t) * N_IDT, GFP_KERNEL);
  if (to_send == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }
  u8 *to_send_p = to_send;

  for (int i = 0; i < N_IDT; i++) {
    memcpy(to_send_p, &idt_entry_info_arr[i], sizeof(idt_entry_u_t));
    to_send_p += sizeof(idt_entry_u_t);
  }

  struct sk_buff *reply_skb = genlmsg_new(sizeof(idt_entry_u_t) * N_IDT, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s():\n", __func__);
    return -ENOMEM;
  }

  void *msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_GET_IDT_ENTRIES);
  if (msg_head == NULL) {
    pr_err("An error occurred in %s()\n", __func__);
    return -ENOMEM;
  }

  int rc = nla_put(reply_skb, KSEC_A_BIN, sizeof(idt_entry_u_t) * N_IDT, to_send);
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
  idt_table = (unsigned __int128 *)lookup("idt_table");

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
