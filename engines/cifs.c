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

// This not part of any installed samba headers
extern struct resolve_context *lpcfg_resolve_context(struct loadparm_context *lp_ctx);

static int extend_file(struct thread_data *td, struct fio_file *f);

struct fio_option cifs_options[] = {
	{
	 .name = "hostname",
	 .lname = "CIFS host",
	 .type = FIO_OPT_STR_STORE,
	 .help = "CIFS host",
	 .off1 = offsetof(struct cifs_options, host),
	 .category = FIO_OPT_C_ENGINE,
	 .group = FIO_OPT_G_CIFS,
	},
	{
	 .name = "username",
	 .lname = "Username of the cifs user",
	 .type = FIO_OPT_STR_STORE,
	 .help = "Username of the cifs user",
	 .off1 = offsetof(struct cifs_options, username),
	 .category = FIO_OPT_C_ENGINE,
	 .group = FIO_OPT_G_CIFS,
	},
	{
	 .name = "password",
	 .lname = "Passsword of the cifs user",
	 .type = FIO_OPT_STR_STORE,
	 .help = "Passsword of the cifs user",
	 .off1 = offsetof(struct cifs_options, password),
	 .category = FIO_OPT_C_ENGINE,
	 .group = FIO_OPT_G_CIFS,
	},
	{
	 .name = "share",
	 .lname = "Name of the cifs share",
	 .type = FIO_OPT_STR_STORE,
	 .help = "Name of the cifs share",
	 .off1 = offsetof(struct cifs_options, share),
	 .category = FIO_OPT_C_ENGINE,
	 .group = FIO_OPT_G_CIFS,
	},
	{
		.name	= NULL,
	},
};

int fio_cifs_init(struct thread_data *td)
{
	struct cifs_data *ld = talloc(NULL, struct cifs_data);
	struct cifs_options *o = td->eo;
	NTSTATUS status;

	memset(ld, 0, sizeof(*ld));

	log_info("Connecting to share: \\\\%s\\%s\n", o->host, o->share);

	// This is only used in the async client
	ld->ev = samba_tevent_context_init(ld);

	// Not sure what this does, but it doesn't connect without it
	gensec_init();

	ld->lp_ctx = loadparm_init_global(false);
	lpcfg_load_default(ld->lp_ctx);
	lpcfg_smbcli_options(ld->lp_ctx, &ld->opts);
	lpcfg_smbcli_session_options(ld->lp_ctx, &ld->sopts);

	// Login crentils
	ld->creds = cli_credentials_init(ld);
	cli_credentials_set_anonymous(ld->creds);

	if (o->username) {
		cli_credentials_parse_string(
			ld->creds,
			o->username,
			CRED_SPECIFIED);
	}
		
	if (o->password) {
		cli_credentials_set_password(
			ld->creds,
			o->password,
			CRED_SPECIFIED);
	}

	// Fills in missing values in crenditals with defaults.
	// Won't connect without it.
	cli_credentials_guess(ld->creds, ld->lp_ctx);

	status = smbcli_full_connection(
		ld,					/* mem_ctx */
		&ld->cli,				/* handle */
		o->host,				/* host */
		lpcfg_smb_ports(ld->lp_ctx),		/* port */
		o->share,				/* sharename */
		NULL,					/* dev type */
		lpcfg_socket_options(ld->lp_ctx),	/* opts: socket */
		ld->creds,				/* opts: cred */
		lpcfg_resolve_context(ld->lp_ctx),	/* resolve ctx */
		ld->ev,					/* event */
		&ld->opts,				/* opts */
		&ld->sopts,				/* opts: session */
		lpcfg_gensec_settings(ld, ld->lp_ctx)	/* opts: grsec */
	);

	if (!NT_STATUS_IS_OK(status)) {
		log_err("smbcli_full_connection() failed: %s %s\n",
			get_friendly_nt_error_msg(status),
			nt_errstr(status));
		goto error;
	}

	log_info("Connected to share: \\\\%s\\%s\n", o->host, o->share);

	td->io_ops->data = ld;
	return 0;

error:
	TALLOC_FREE(ld);
	return -EIO;
}

void fio_cifs_cleanup(struct thread_data *td)
{
	struct cifs_data *ld = td->io_ops->data;

	if (!ld) return;

	smbcli_tdis(ld->cli);
	TALLOC_FREE(ld);
}

static int open_flags(struct thread_data *td)
{
	int flags = 0;

	if (td_write(td)) {
		if (!read_only)
			flags = O_RDWR;
	} else if (td_read(td)) {
		if (!read_only)
			flags = O_RDWR;
		else
			flags = O_RDONLY;
	}

        if (td->o.create_on_open)
                flags |= O_CREAT;

	return flags;
}

int fio_cifs_open_file(struct thread_data *td, struct fio_file *f)
{
	int flags = open_flags(td);
	struct cifs_data *ld = td->io_ops->data;
	struct cifs_options *o = td->eo;

	ld->fnum = smbcli_open(ld->cli->tree, f->file_name, flags, DENY_NONE);

	if (ld->fnum == -1) {
		log_err("smbcli_open() failed\n");
		return ld->fnum;
	}

	log_info("Opened file: \\\\%s\\%s\%s\n", o->host, o->share,
		f->file_name);

	// Setup file (grow / shrink) if needed.
	return extend_file(td, f);
}

int fio_cifs_close_file(struct thread_data *td, struct fio_file *f)
{
	struct cifs_data *ld = td->io_ops->data;
	struct cifs_options *o = td->eo;
	NTSTATUS status = smbcli_close(ld->cli->tree, ld->fnum);

	if (!NT_STATUS_IS_OK(status)) {
		log_err("smbcli_close() failed: %s %s\n",
			get_friendly_nt_error_msg(status),
			nt_errstr(status));
		return -EIO;
	}

	log_info("Closed file: \\\\%s\\%s\%s\n", o->host, o->share,
		f->file_name);

	return 0;
}

int fio_cifs_unlink_file(struct thread_data *td, struct fio_file *f)
{
	struct cifs_data *ld = td->io_ops->data;
	struct cifs_options *o = td->eo;
	NTSTATUS status;
	
	status = smbcli_unlink(ld->cli->tree, f->file_name);

	if (!NT_STATUS_IS_OK(status)) {
		log_err("smbcli_unlink() failed: %s %s\n",
			get_friendly_nt_error_msg(status),
			nt_errstr(status));
		return -EIO;
	}

	log_info("Deleted file: \\\\%s\\%s\%s\n", o->host, o->share,
		 f->file_name);

	return 0;
}

int fio_cifs_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct cifs_data *ld = td->io_ops->data;
	struct cifs_options *o = td->eo;
	size_t size;
	NTSTATUS status;

	// This gets called before the engine is initlized
	if (!ld) return 0;

	status = smbcli_getattrE(ld->cli->tree, ld->fnum, NULL, &size, NULL,
				 NULL, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		log_err("smbcli_getattrE() failed: %s %s\n",
			get_friendly_nt_error_msg(status),
			nt_errstr(status));
		return -EIO;
	}

	log_info("stat: \\\\%s\\%s\%s\n", o->host, o->share,
		f->file_name);

	f->real_file_size = size;
	fio_file_set_size_known(f);

	return 0;
}

// Since we're not using the normal generic_open_* fd, we can't count on fio 
// to extend the file for us
static
int extend_file(struct thread_data *td, struct fio_file *f)
{
	size_t size = 0;
	struct cifs_data *ld = td->io_ops->data;
	int ret = 0;
	NTSTATUS status;
	char* tmp_data;

	// Find current size
	status = smbcli_getattrE(ld->cli->tree, ld->fnum, NULL, &size, NULL,
				 NULL, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		log_err("smbcli_getattrE() failed: %s %s\n",
			get_friendly_nt_error_msg(status),
			nt_errstr(status));
		return -EIO;
	}

	if (size == f->real_file_size)
		return 0;

	// Too large, truncate
	if (size < f->real_file_size) {
		status = smbcli_ftruncate(ld->cli->tree, ld->fnum,
					  f->real_file_size);

		if (!NT_STATUS_IS_OK(status)) {
			log_err("smbcli_ftruncate() failed: %s %s\n",
				get_friendly_nt_error_msg(status),
				nt_errstr(status));
			return -EIO;
		}

		return 0;
	}

	// File is too small

	// fill the file, copied from extend_file
	if ((tmp_data = malloc(td->o.max_bs[DDIR_WRITE])) == NULL)
		return -ENOMEM;

	for (size_t left = f->real_file_size - size; left & !td->terminate; ) {
		uint16_t write_flags = 0;
		unsigned bs = td->o.max_bs[DDIR_WRITE];
		ssize_t  len;

		if (td->o.create_fsync) {
			// Disable write caching (according to header)
			write_flags |= 0x0001;
		}

		if (bs > left)
			bs = left;

		fill_io_buffer(td, tmp_data, bs, bs);

		len = smbcli_write(ld->cli->tree, ld->fnum, write_flags,
				   tmp_data, size, bs);

		if (len < 0) {
			if (errno == ENOSPC && td->o.fill_device) {
				log_info("fio: ENOSPC on laying out "
					 "file, stopping\n");
				break;
			}

			td_verror(td, errno, "write");
			ret = -EIO;
			break;
		}

		size += len;
		left -= len;
	}

	free(tmp_data);
	return ret;
}
