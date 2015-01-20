/*
 * cifs sync
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"

#include "cifs.h"

#define LAST_POS(f)	((f)->engine_data)

static int fio_io_end(struct thread_data *td, struct io_u *io_u, int ret)
{
	if (io_u->file && ret >= 0 && ddir_rw(io_u->ddir))
		LAST_POS(io_u->file) = io_u->offset + ret;

	if (ret != (int) io_u->xfer_buflen) {
		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else
			io_u->error = errno;
	}

	if (io_u->error)
		td_verror(td, io_u->error, "xfer");

	return FIO_Q_COMPLETED;
}

static int fio_cifs_queue(struct thread_data *td, struct io_u *io_u)
{
	struct cifs_data *ld = td->io_ops->data;
	ssize_t ret;

	if (io_u->ddir == DDIR_READ) {
		ret = smbcli_read(ld->cli->tree, ld->fnum,
			io_u->xfer_buf, io_u->offset, io_u->xfer_buflen);
	} else if (io_u->ddir == DDIR_WRITE) {
		uint16_t write_flags = 0;
		ret = smbcli_write(ld->cli->tree, ld->fnum, write_flags,
			io_u->xfer_buf, io_u->offset, io_u->xfer_buflen);
	} else {
		log_err("unsupported operation.\n");
		return -EINVAL;
	}

	if (ret < 0) {
		log_info("CIFS IO error Op: %i, fnum: %i, offset: %llu, "
			 "len: %lu, ret: %lld",
			 io_u->ddir, ld->fnum, io_u->offset,
			 io_u->xfer_buflen, (long long int) ret);
	}

	return fio_io_end(td, io_u, ret);
}

static struct ioengine_ops ioengine = {
	.name			= "cifs_sync",
	.version		= FIO_IOOPS_VERSION,
	.init			= fio_cifs_init,
	.cleanup		= fio_cifs_cleanup,
	.queue			= fio_cifs_queue,
	.open_file		= fio_cifs_open_file,
	.close_file		= fio_cifs_close_file,
	.unlink_file		= fio_cifs_unlink_file,
	.get_file_size		= fio_cifs_get_file_size,
	.options		= cifs_options,
	.option_struct_size	= sizeof(struct cifs_options),
	.flags			= FIO_SYNCIO | FIO_DISKLESSIO,
};

static void fio_init fio_cifs_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_cifs_unregister(void)
{
	unregister_ioengine(&ioengine);
}
