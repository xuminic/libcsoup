#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "libcsoup.h"

static	struct	TestBlk	{
	CSCLNK	link;
	char	value[32];
} testblock[16];

static int csc_cdll_basic_function(void)
{
	struct	TestBlk	*tblk;
	CSCLNK	*root, *node;
	int	i;

	for (i = 0, root = NULL; i < 16; i++) {
		testblock[i].value[0] = 'A' + i;
		testblock[i].value[1] = 0;
		root = csc_cdl_insert_head(root, &testblock[i].link);
	}
	slogz("Stack: ");
	for (node = root; node; node = csc_cdl_next(root, node)) {
		tblk = (struct TestBlk *) node;
		slogz("%s ", tblk->value);
	}
	slogz("\n");

	for (i = 0, root = NULL; i < 16; i++) {
		testblock[i].value[0] = 'A' + i;
		testblock[i].value[1] = 0;
		root = csc_cdl_insert_tail(root, &testblock[i].link);
	}
	slogz("FIFO: ");
	for (node = root; node; node = csc_cdl_next(root, node)) {
		tblk = (struct TestBlk *) node;
		slogz("%s ", tblk->value);
	}
	slogz("\n");
	return 0;
}

static int csc_cdll_list_function(void)
{
	CSCLNK	*node, *anchor = NULL;
	char	*cont[] = { "Hello", "World", "Peace", "Love", "Bullshit", NULL };

	
	node = csc_cdl_list_alloc_head(&anchor, 16);
	strcpy((char*)&node[1], cont[0]);

	node = csc_cdl_list_alloc_head(&anchor, 16);
	strcpy((char*)&node[1], cont[1]);

	node = csc_cdl_list_alloc_tail(&anchor, 16);                
	strcpy((char*)&node[1], cont[2]);

	for (node = anchor; node; node = csc_cdl_next(anchor, node)) {
		printf("%s\n", (char*)&node[1]);
	}
	return 0;
}

int csc_cdll_main(void *rtime, int argc, char **argv)
{
	/* stop the compiler complaining */
	(void) rtime; (void) argc; (void) argv;
	csc_cdll_basic_function();
}

struct	clicmd	cdll_cmd = {
	"csc_cdll", csc_cdll_main, NULL, "Testing the functions of doubly circular link list"
};

extern  struct  clicmd  cdll_cmd;

