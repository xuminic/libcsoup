#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "libcsoup.h"

static	struct	TestBlk	{
	CSCLNK	link;
	char	value[32];
} testblock[16];


static int cdc_cdll_safe_mode_verify(void)
{
	CSCLNK	*root, testnode[2];

	root = csc_cdl_insert_head(NULL, &testnode[0]);
	root->prev = NULL;
	slogz("Verification: CSCLNK by lib %d and by program %d\n", 
			csc_cdl_node_size(NULL), sizeof(CSCLNK));
#ifdef	CFG_CDLL_SAFE
	if (csc_cdl_insert_after(root, &testnode[1]) == 0) {
		slogz("Fatal: this program was compiled with -DCFG_CDLL_SAFE but the library was not!\n");
		return -1;
	}
#else
	if (csc_cdl_insert_after(root, &testnode[1]) < 0) {
		slogz("Fatal: the library was compiled with -DCFG_CDLL_SAFE but the program was not!\n");
		return -1;
	}
#endif
	slogz("Verification: succeeded.\n");
	return 0;
}

static int csc_cdll_print_test_block(CSCLNK *root)
{
	struct	TestBlk	*tblk;
	CSCLNK	*node;

	for (node = root; node; node = csc_cdl_next(root, node)) {
		tblk = (struct TestBlk *) node;
		slogz("%s ", tblk->value);
	}
	slogz("\n");
	return 0;
}

static int csc_cdll_my_compare(void *src, void *dst)
{
	return strcmp(src, dst);
}

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
	slogz("Stack:  ");
	csc_cdll_print_test_block(root);

	for (i = 0, root = NULL; i < 16; i++) {
		testblock[i].value[0] = 'A' + i;
		testblock[i].value[1] = 0;
		root = csc_cdl_insert_tail(root, &testblock[i].link);
	}
	slogz("FIFO:   ");
	csc_cdll_print_test_block(root);

	node = csc_cdl_search(root, NULL, csc_cdll_my_compare, "D");
	tblk = (struct TestBlk *) node;
	if (tblk) {
		slogz("Search: %s\n", tblk->value);
	}

	for (i = 0, node = root; node; node = csc_cdl_next(root, node), i++) {
		if (i & 1) {
			root = csc_cdl_remove(root, node);
		}
	}
	slogz("Remove: ");
	csc_cdll_print_test_block(root);

	i = 3;
	node = csc_cdl_goto(root, i);
	tblk = (struct TestBlk *) node;
	if (tblk) {
		slogz("Goto/%d: %s\n", i, tblk->value);
	}

	slogz("State:  %d\n", csc_cdl_quantity(root));
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

	slogz("State:  %d\n", csc_cdl_list_state(&anchor));
	for (node = anchor; node; node = csc_cdl_next(anchor, node)) {
		slogz("%s\n", (char*)&node[1]);
	}

	csc_cdl_list_destroy(&anchor);
	return 0;
}

int csc_cdll_main(void *rtime, int argc, char **argv)
{
	/* stop the compiler complaining */
	(void) rtime; (void) argc; (void) argv;
	
	if (cdc_cdll_safe_mode_verify() < 0) {
		return -1;	/* wrong compiling macro */
	}

	csc_cdll_basic_function();
	csc_cdll_list_function();
	return 0;
}

struct	clicmd	cdll_cmd = {
	"csc_cdll", csc_cdll_main, NULL, "Testing the functions of doubly circular link list"
};

extern  struct  clicmd  cdll_cmd;

