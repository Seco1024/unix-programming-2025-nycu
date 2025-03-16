#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

#include "cryptomod.h"  

#define DEVICE_NAME "cryptodev"
#define CLASS_NAME  "crypto"
#define PROC_NAME   "cryptomod"

#define MAX_BUFFER_SIZE 1024

static atomic64_t global_bytes_read = ATOMIC64_INIT(0);
static atomic64_t global_bytes_written = ATOMIC64_INIT(0);
static uint64_t byte_frequency[256] = {0};
static DEFINE_MUTEX(freq_lock);

struct cryptomod_file_data {
	bool setup_done;
	bool finalized;
	enum CryptoMode c_mode;  
	enum IOMode io_mode;   
	int key_len;         
	unsigned char key[CM_KEY_MAX_LEN]; 

	unsigned char in_buf[MAX_BUFFER_SIZE];
	size_t in_buf_size;
	unsigned char *out_buf;
	size_t out_buf_size;
	size_t out_buf_offset;

	struct crypto_skcipher *skcipher;
	struct mutex lock;
};

static dev_t devnum;
static struct cdev c_dev;
static struct class *crypto_class;

static int process_block(struct cryptomod_file_data *data,
						const unsigned char *in,
						unsigned char *out,
						bool encrypt)
{
	struct skcipher_request *req;
	struct scatterlist sg_in, sg_out;
	int ret;

	sg_init_one(&sg_in, in, CM_BLOCK_SIZE);
	sg_init_one(&sg_out, out, CM_BLOCK_SIZE);

	req = skcipher_request_alloc(data->skcipher, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	skcipher_request_set_crypt(req, &sg_in, &sg_out, CM_BLOCK_SIZE, NULL);
	if (encrypt)
		ret = crypto_skcipher_encrypt(req);
	else
		ret = crypto_skcipher_decrypt(req);

	skcipher_request_free(req);
	return ret;
}


static long cryptomod_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct cryptomod_file_data *data = f->private_data;
	int ret = 0;
	struct CryptoSetup setup;

	mutex_lock(&data->lock);
	switch (cmd) {
	case CM_IOC_SETUP:
		if (!arg || copy_from_user(&setup, (void __user *)arg, sizeof(setup))) {
			ret = -EINVAL;
			break;
		}
		if (setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32) {
			ret = -EINVAL;
			break;
		}
		if (setup.c_mode != ENC && setup.c_mode != DEC) {
			ret = -EINVAL;
			break;
		}
		if (setup.io_mode != BASIC && setup.io_mode != ADV) {
			ret = -EINVAL;
			break;
		}
		if (data->setup_done && data->skcipher) {
			crypto_free_skcipher(data->skcipher);
			data->skcipher = NULL;
		}
		data->skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
		if (IS_ERR(data->skcipher)) {
			ret = PTR_ERR(data->skcipher);
			data->skcipher = NULL;
			break;
		}

		ret = crypto_skcipher_setkey(data->skcipher, setup.key, setup.key_len);
		if (ret) {
			crypto_free_skcipher(data->skcipher);
			data->skcipher = NULL;
			ret = -EINVAL;
			break;
		}
		data->c_mode = setup.c_mode;
		data->io_mode = setup.io_mode;
		data->key_len = setup.key_len;
		memcpy(data->key, setup.key, setup.key_len);
		data->setup_done = true;
		data->in_buf_size = 0;
		if (data->out_buf) {
			kfree(data->out_buf);
			data->out_buf = NULL;
		}
		data->out_buf_size = 0;
		data->out_buf_offset = 0;
		data->finalized = false;
		break;

	case CM_IOC_FINALIZE:
		if (!data->setup_done) {
			ret = -EINVAL;
			break;
		}
		if (data->finalized) {
			ret = -EINVAL;
			break;
		}
		if (data->io_mode == BASIC) {
			if (data->c_mode == ENC) {
				int pad = CM_BLOCK_SIZE - (data->in_buf_size % CM_BLOCK_SIZE);
				if (pad == 0)
					pad = CM_BLOCK_SIZE;
				if (data->in_buf_size + pad > MAX_BUFFER_SIZE) {
					ret = -EINVAL;
					break;
				}
				memset(data->in_buf + data->in_buf_size, pad, pad);
				data->in_buf_size += pad;
				data->out_buf = kmalloc(data->in_buf_size, GFP_KERNEL);
				if (!data->out_buf) {
					ret = -ENOMEM;
					break;
				}
				data->out_buf_size = data->in_buf_size;
				for (size_t i = 0; i < data->in_buf_size; i += CM_BLOCK_SIZE) {
					ret = process_block(data, data->in_buf + i, data->out_buf + i, true);
					if (ret)
						break;
				}
			} else { 
				if (data->in_buf_size % CM_BLOCK_SIZE != 0 || data->in_buf_size == 0) {
					ret = -EINVAL;
					break;
				}
				data->out_buf = kmalloc(data->in_buf_size, GFP_KERNEL);
				if (!data->out_buf) {
					ret = -ENOMEM;
					break;
				}
				data->out_buf_size = data->in_buf_size;
				for (size_t i = 0; i < data->in_buf_size; i += CM_BLOCK_SIZE) {
					ret = process_block(data, data->in_buf + i, data->out_buf + i, false);
					if (ret)
						break;
				}
				int pad = data->out_buf[data->out_buf_size - 1];
				if (pad <= 0 || pad > CM_BLOCK_SIZE) {
					ret = -EINVAL;
					break;
				}
				for (size_t i = data->out_buf_size - pad; i < data->out_buf_size; i++) {
					if (data->out_buf[i] != pad) {
						ret = -EINVAL;
						break;
					}
				}
				if (ret)
					break;
				data->out_buf_size -= pad;
			}
		} else { 
			if (data->c_mode == ENC) {
				if (data->in_buf_size >= 0) {
					int pad = CM_BLOCK_SIZE - (data->in_buf_size % CM_BLOCK_SIZE);
					if (pad == 0)
						pad = CM_BLOCK_SIZE;
					unsigned char block[CM_BLOCK_SIZE];
					memset(block, pad, CM_BLOCK_SIZE);
					memcpy(block, data->in_buf, data->in_buf_size);
					{
						size_t new_size = data->out_buf_size + CM_BLOCK_SIZE;
						unsigned char *tmp = krealloc(data->out_buf, new_size, GFP_KERNEL);
						if (!tmp) {
							ret = -ENOMEM;
							break;
						}
						data->out_buf = tmp;
						ret = process_block(data, block, data->out_buf + data->out_buf_size, true);
						if (ret)
							break;
						data->out_buf_size = new_size;
					}
					data->in_buf_size = 0;
				}
			} else { 
				if (data->in_buf_size < CM_BLOCK_SIZE) {
					ret = -EINVAL;
					break;
				}
				{
					size_t new_size = data->out_buf_size + CM_BLOCK_SIZE;
					unsigned char *tmp = krealloc(data->out_buf, new_size, GFP_KERNEL);
					if (!tmp) {
						ret = -ENOMEM;
						break;
					}
					data->out_buf = tmp;
					ret = process_block(data, data->in_buf, data->out_buf + data->out_buf_size, false);
					if (ret)
						break;
					data->out_buf_size = new_size;
				}
				data->in_buf_size = 0;
				int pad = data->out_buf[data->out_buf_size - 1];
				if (pad <= 0 || pad > CM_BLOCK_SIZE) {
					ret = -EINVAL;
					break;
				}
				for (size_t i = data->out_buf_size - pad; i < data->out_buf_size; i++) {
					if (data->out_buf[i] != pad) {
						ret = -EINVAL;
						break;
					}
				}
				if (ret)
					break;
				data->out_buf_size -= pad;
			}
		}
		if (!ret) {
			data->finalized = true;
		}
		break;

	case CM_IOC_CLEANUP:
		data->in_buf_size = 0;
		if (data->out_buf) {
			kfree(data->out_buf);
			data->out_buf = NULL;
		}
		data->out_buf_size = 0;
		data->out_buf_offset = 0;
		data->finalized = false;
		break;

	case CM_IOC_CNT_RST:
		atomic64_set(&global_bytes_read, 0);
		atomic64_set(&global_bytes_written, 0);
		mutex_lock(&freq_lock);
		memset(byte_frequency, 0, sizeof(byte_frequency));
		mutex_unlock(&freq_lock);
		break;

	default:
		ret = -EINVAL;
		break;
	}
	mutex_unlock(&data->lock);
	return ret;
}

static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf,
								size_t len, loff_t *off)
{
	struct cryptomod_file_data *data = f->private_data;
	ssize_t copied = 0;
	int ret = 0;

	mutex_lock(&data->lock);
	if (!data->setup_done || data->finalized) {
		mutex_unlock(&data->lock);
		return -EINVAL;
	}

	if (data->io_mode == BASIC) {
		size_t space = MAX_BUFFER_SIZE - data->in_buf_size;
		size_t to_copy = min(len, space);
		if (to_copy == 0) {
			mutex_unlock(&data->lock);
			return -EAGAIN;
		}
		if (copy_from_user(data->in_buf + data->in_buf_size, buf, to_copy)) {
			mutex_unlock(&data->lock);
			return -EBUSY;
		}
		data->in_buf_size += to_copy;
		copied = to_copy;
	} else {
		if (copy_from_user(data->in_buf + data->in_buf_size, buf, len)) {
			mutex_unlock(&data->lock);
			return -EBUSY;
		}
		data->in_buf_size += len;
		copied = len;

		if (data->c_mode == ENC) {
			while (data->in_buf_size >= CM_BLOCK_SIZE) {
				unsigned char block_out[CM_BLOCK_SIZE];
				ret = process_block(data, data->in_buf, block_out, true);
				if (ret) {
					mutex_unlock(&data->lock);
					return ret;
				}
				size_t new_size = data->out_buf_size + CM_BLOCK_SIZE;
				unsigned char *tmp = krealloc(data->out_buf, new_size, GFP_KERNEL);
				if (!tmp) {
					mutex_unlock(&data->lock);
					return -ENOMEM;
				}
				data->out_buf = tmp;
				memcpy(data->out_buf + data->out_buf_size, block_out, CM_BLOCK_SIZE);
				data->out_buf_size = new_size;

				memmove(data->in_buf, data->in_buf + CM_BLOCK_SIZE, data->in_buf_size - CM_BLOCK_SIZE);
				data->in_buf_size -= CM_BLOCK_SIZE;
			}
		} else {
			while (data->in_buf_size >= 2 * CM_BLOCK_SIZE) {
				unsigned char block_out[CM_BLOCK_SIZE];
				ret = process_block(data, data->in_buf, block_out, false);
				if (ret) {
					mutex_unlock(&data->lock);
					return ret;
				}
				size_t new_size = data->out_buf_size + CM_BLOCK_SIZE;
				unsigned char *tmp = krealloc(data->out_buf, new_size, GFP_KERNEL);
				if (!tmp) {
					mutex_unlock(&data->lock);
					return -ENOMEM;
				}
				data->out_buf = tmp;
				memcpy(data->out_buf + data->out_buf_size, block_out, CM_BLOCK_SIZE);
				data->out_buf_size = new_size;

				memmove(data->in_buf, data->in_buf + CM_BLOCK_SIZE, data->in_buf_size - CM_BLOCK_SIZE);
				data->in_buf_size -= CM_BLOCK_SIZE;
			}
		}
	}
	atomic64_add(copied, &global_bytes_written);
	mutex_unlock(&data->lock);
	return copied;
}

static ssize_t cryptomod_dev_read(struct file *f, char __user *buf,
								size_t len, loff_t *off)
{
	struct cryptomod_file_data *data = f->private_data;
	ssize_t available, to_copy;

	mutex_lock(&data->lock);
	if (!data->setup_done) {
		mutex_unlock(&data->lock);
		return -EINVAL;
	}
	available = data->out_buf_size - data->out_buf_offset;
	if (available <= 0) {
		if (!data->finalized) {
			mutex_unlock(&data->lock);
			return -EAGAIN;
		} else {
			mutex_unlock(&data->lock);
			return 0;
		}
	}
	to_copy = min(len, (size_t)available);
	if (copy_to_user(buf, data->out_buf + data->out_buf_offset, to_copy)) {
		mutex_unlock(&data->lock);
		return -EBUSY;
	}
	data->out_buf_offset += to_copy;
	atomic64_add(to_copy, &global_bytes_read);

	if (data->c_mode == ENC) {
		mutex_lock(&freq_lock);
		for (size_t i = 0; i < to_copy; i++)
			byte_frequency[data->out_buf[data->out_buf_offset - to_copy + i]]++;
		mutex_unlock(&freq_lock);
	}
	if (data->out_buf_offset == data->out_buf_size) {
        kfree(data->out_buf);
        data->out_buf = NULL;
        data->out_buf_size = 0;
        data->out_buf_offset = 0;
    }
	mutex_unlock(&data->lock);
	return to_copy;
}

static int cryptomod_proc_read(struct seq_file *m, void *v)
{
	int i, j;
	seq_printf(m, "%lld %lld\n", atomic64_read(&global_bytes_read), atomic64_read(&global_bytes_written));
	mutex_lock(&freq_lock);
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 16; j++)
			seq_printf(m, "%llu ", byte_frequency[i * 16 + j]);
		seq_printf(m, "\n");
	}
	mutex_unlock(&freq_lock);
	return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, cryptomod_proc_read, NULL);
}

static const struct proc_ops cryptomod_proc_fops = {
	.proc_open    = cryptomod_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static char *cryptomod_devnode(const struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0666;
	return NULL;
}

static int cryptomod_dev_open(struct inode *i, struct file *f)
{
	struct cryptomod_file_data *data;
	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	data->in_buf_size = 0;
	data->out_buf = NULL;
	data->out_buf_size = 0;
	data->out_buf_offset = 0;
	data->setup_done = false;
	data->finalized = false;
	data->skcipher = NULL;
	mutex_init(&data->lock);
	f->private_data = data;
	return 0;
}

static int cryptomod_dev_close(struct inode *i, struct file *f)
{
	struct cryptomod_file_data *data = f->private_data;
	if (data->out_buf)
		kfree(data->out_buf);
	if (data->skcipher)
		crypto_free_skcipher(data->skcipher);
	kfree(data);
	return 0;
}

static const struct file_operations cryptomod_fops = {
	.owner          = THIS_MODULE,
	.open           = cryptomod_dev_open,
	.read           = cryptomod_dev_read,
	.write          = cryptomod_dev_write,
	.unlocked_ioctl = cryptomod_dev_ioctl,
	.release        = cryptomod_dev_close,
};


static int __init cryptomod_init(void)
{
	int ret;
	ret = alloc_chrdev_region(&devnum, 0, 1, DEVICE_NAME);
	if (ret < 0) {
		return ret;
	}
	crypto_class = class_create(CLASS_NAME);
	if (IS_ERR(crypto_class)) {
		unregister_chrdev_region(devnum, 1);
		return PTR_ERR(crypto_class);
	}
	crypto_class->devnode = cryptomod_devnode;
	if (device_create(crypto_class, NULL, devnum, NULL, DEVICE_NAME) == NULL) {
		class_destroy(crypto_class);
		unregister_chrdev_region(devnum, 1);
		return -1;
	}
	cdev_init(&c_dev, &cryptomod_fops);
	ret = cdev_add(&c_dev, devnum, 1);
	if (ret < 0) {
		device_destroy(crypto_class, devnum);
		class_destroy(crypto_class);
		unregister_chrdev_region(devnum, 1);
		return ret;
	}

	if (!proc_create(PROC_NAME, 0, NULL, &cryptomod_proc_fops)) {
		cdev_del(&c_dev);
		device_destroy(crypto_class, devnum);
		class_destroy(crypto_class);
		unregister_chrdev_region(devnum, 1);
		return -ENOMEM;
	}
	return 0;
}

static void __exit cryptomod_cleanup(void)
{
	remove_proc_entry(PROC_NAME, NULL);
	cdev_del(&c_dev);
	device_destroy(crypto_class, devnum);
	class_destroy(crypto_class);
	unregister_chrdev_region(devnum, 1);
}

module_init(cryptomod_init);
module_exit(cryptomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seco1024");
MODULE_DESCRIPTION("Unix Lab2.");
