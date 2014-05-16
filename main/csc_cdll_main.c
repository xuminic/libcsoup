#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "libcsoup.h"

int csc_cdll_main(void *rtime, int argc, char **argv)
{
	CSCLNK	*node, *anchor = NULL;
	char	*cont[] = { "Hello", "World", "Peace", "Love", "Bullshit", NULL };

	/* stop the compiler complaining */
	(void) rtime; (void) argc; (void) argv;
	
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
struct	clicmd	cdll_cmd = {
	"csc_cdll", csc_cdll_main, NULL, "Testing the functions of doubly circular link list"
};

extern  struct  clicmd  cdll_cmd;

