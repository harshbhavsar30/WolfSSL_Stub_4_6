/* module_hooks.c -- module load/unload hooks for libwolfssl.ko
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * https://www.wolfssl.com
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#ifndef NO_CRYPT_TEST
#include <wolfcrypt/test/test.h>
#include <linux/delay.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static int __init wolfssl_init(void)
#else
static int wolfssl_init(void)
#endif
{
    int ret;
#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        pr_err("wolfCrypt_Init() failed: %s", wc_GetErrorString(ret));
        return -ENOTRECOVERABLE;
    }
#else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        pr_err("wolfSSL_Init() failed: %s", wc_GetErrorString(ret));
        return -ENOTRECOVERABLE;
    }
#endif

#ifndef NO_CRYPT_TEST
    ret = wolfcrypt_test(NULL);
    if (ret < 0) {
        pr_err("wolfcrypt self-test failed.");
        msleep(10);
        return -ENOTRECOVERABLE;
    }
    pr_info("wolfCrypt self-test passed.\n");
#endif

#ifdef WOLFCRYPT_ONLY
    pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " loaded. See https://www.wolfssl.com/ for information.\n");
#else
    pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " loaded. See https://www.wolfssl.com/ for information.\n");
#endif

    pr_info("Copyright (C) 2006-2020 wolfSSL Inc. All Rights Reserved.\n");

    return 0;
}

module_init(wolfssl_init);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static void __exit wolfssl_exit(void)
#else
static void wolfssl_exit(void)
#endif
{
    int ret;
#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Cleanup();
    if (ret != 0)
        pr_err("wolfCrypt_Cleanup() failed: %s", wc_GetErrorString(ret));
    else
        pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#else
    ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS)
        pr_err("wolfSSL_Cleanup() failed: %s", wc_GetErrorString(ret));
    else
        pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#endif

    return;
}

module_exit(wolfssl_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("https://www.wolfssl.com/");
MODULE_DESCRIPTION("libwolfssl cryptographic and protocol facilities");
MODULE_VERSION(LIBWOLFSSL_VERSION_STRING);
