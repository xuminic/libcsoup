
/* CSOUP Object Oriented Framework */

/* CSOUP Object Oriented Framework: data type */
#define	COO_DTYPE_NONE		0	/* empty MUnit */
#define COO_DTYPE_I32		1
#define COO_DTYPE_I64		2
#define COO_DTYPE_STRING	3	/* pointer to string */
#define COO_DTYPE_POINTER	4	/* pointer to binary */
#define COO_DTYPE_FUNC		10	/* int (*func)(void) */
#define COO_DTYPE_MASK		0xff
#define COO_DTYPE_GET(f)	((f) & COO_DTYPE_MASK)
#define COO_DTYPE_SET(f,n)	(((f) &~ COO_DTYPE_MASK) | COO_DTYPE_GET(n))

/* CSOUP Object Oriented Framework: memory type */
#define COO_MTYPE_PREDEF	0	/* pre-defined memory */
#define COO_MTYPE_ALLOC		0x100	/* allocated memory */
#define COO_MTYPE_LINK		0x200	/* dynamic link list */
#define COO_MTYPE_MASK		0xf00
#define COO_MTYPE_GET(f)	((f) & COO_MTYPE_MASK)
#define COO_MTYPE_SET(f,n)	(((f) &~ COO_MTYPE_MASK) | COO_MTYPE_GET(n))

/* CSOUP Object Oriented Framework: access mode */
#define COO_ACCM_PUBLIC		0
#define COO_ACCM_PRIVATE	0x1000
#define COO_ACCM_PROTECT	0x2000
#define COO_ACCM_MASK		0xf000
#define COO_ACCM_GET(f)		((f) & COO_ACCM_MASK)
#define COO_ACCM_SET(f,n)	(((f) &~ COO_ACCM_MASK) | COO_ACCM_GET(n))

typedef int (*MFunc)(void);

typedef	struct	{	/* define the meta-unit */
	int	id;
	int	type;
	union	{
		int		d_int;
		long long	d_int64;
		char		*d_string;
		void		*d_point;
		MFunc		d_func;
	};
} MUnit;

typedef	struct	{
	//CSCLNK	parent;

	char	*cname;

	MUnit	repo;
	int	total;

	MUnit	pool[1];	/* attribution repository begin */
} CCLASS;


