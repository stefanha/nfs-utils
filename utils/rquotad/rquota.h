#define RQ_PATHLEN 1024

struct getquota_args {
	char *gqa_pathp;
	int gqa_uid;
};
typedef struct getquota_args getquota_args;
bool_t xdr_getquota_args();


struct ext_getquota_args {
	char *gqa_pathp;
	int gqa_type;
	int gqa_id;
};
typedef struct ext_getquota_args ext_getquota_args;
bool_t xdr_ext_getquota_args();


struct rquota {
	int rq_bsize;
	bool_t rq_active;
	u_int rq_bhardlimit;
	u_int rq_bsoftlimit;
	u_int rq_curblocks;
	u_int rq_fhardlimit;
	u_int rq_fsoftlimit;
	u_int rq_curfiles;
	u_int rq_btimeleft;
	u_int rq_ftimeleft;
};
typedef struct rquota rquota;
bool_t xdr_rquota();


enum gqr_status {
	Q_OK = 1,
	Q_NOQUOTA = 2,
	Q_EPERM = 3,
};
typedef enum gqr_status gqr_status;
bool_t xdr_gqr_status();


struct getquota_rslt {
	gqr_status status;
	union {
		rquota gqr_rquota;
	} getquota_rslt_u;
};
typedef struct getquota_rslt getquota_rslt;
bool_t xdr_getquota_rslt();


#define RQUOTAPROG ((u_long)100011)
#define RQUOTAVERS ((u_long)1)
#define RQUOTAPROC_GETQUOTA ((u_long)1)
extern getquota_rslt *rquotaproc_getquota_1();
#define RQUOTAPROC_GETACTIVEQUOTA ((u_long)2)
extern getquota_rslt *rquotaproc_getactivequota_1();
#define EXT_RQUOTAVERS ((u_long)2)
extern getquota_rslt *rquotaproc_getquota_2();
extern getquota_rslt *rquotaproc_getactivequota_2();

