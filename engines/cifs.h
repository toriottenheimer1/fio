#include <stdbool.h>
#include <stdint.h>

#include <samba_util.h>
#include <smb_cli.h>
#include <credentials.h>
#include <param.h>
#include <gensec.h>

struct cifs_options {
	struct thread_data *td;
	const char* host;
	const char* username;
	const char* password;
	const char* share;
};

struct cifs_data {
	/* settings */
	struct loadparm_context* lp_ctx;
	struct cli_credentials* creds;
	struct smbcli_options opts;
	struct smbcli_session_options sopts;

	/* client */
	struct smbcli_state *cli;

	/* async */
	struct tevent_context *ev;
	struct tevent_req *req;

	/* fd */
	int fnum;
};

extern struct fio_option cifs_options[];

extern int fio_cifs_init(struct thread_data *td);
extern void fio_cifs_cleanup(struct thread_data *td);

extern int fio_cifs_open_file(struct thread_data *td, struct fio_file *f);
extern int fio_cifs_close_file(struct thread_data *td, struct fio_file *f);
extern int fio_cifs_unlink_file(struct thread_data *td, struct fio_file *f);
extern int fio_cifs_get_file_size(struct thread_data *td, struct fio_file *f);


