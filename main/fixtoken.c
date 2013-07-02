 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


static	struct	{
	char	*delim;
	char	*content;
} testbl[] = {
	{ "# :",	"#abc  wdc:have:::#:debug" },
	{ " ",		"  abc bcd 'sad str sf  ' sdf > asdf" },
	{ NULL, NULL }
};

int fixtoken_test(char *content, char *delim)
{
	char	buf[256], *argv[32];
	int	i, argc;

	printf("PARSING   {%s} by {%s}\n", content, delim);

	strcpy(buf, content);
	argc = fixtoken(buf, argv, sizeof(argv)/sizeof(char*), delim);
	printf("FIXTOKEN: ");
	for (i = 0; i < argc; i++) {
		printf("{%s} ", argv[i]);
	}
	printf("\n");

	strcpy(buf, content);
	argc = ziptoken(buf, argv, sizeof(argv)/sizeof(char*), delim);
	printf("ZIPTOKEN: ");
	for (i = 0; i < argc; i++) {
		printf("{%s} ", argv[i]);
	}
	printf("\n");

	strcpy(buf, content);
	argc = mkargv(buf, argv, sizeof(argv)/sizeof(char*));
	printf("MKARGV:   ");
	for (i = 0; i < argc; i++) {
		printf("{%s} ", argv[i]);
	}
	printf("\n\n");
	return 0;
}

int fixtoken_main(void)
{
	int	i;

	for (i = 0; testbl[i].delim; i++) {
		fixtoken_test(testbl[i].content, testbl[i].delim);
	}
	return 0;
}

int fixtoken_run(void)
{
	char	buf[256];

	printf("Press Ctrl-D or 'quit' command to quit.\n");
	while (1) {
		printf("IN> ");
		if (fgets(buf, 256, stdin) == NULL) {
			break;
		}

		buf[strlen(buf) - 1] = 0;
		if (!strcmp(buf, "quit") || !strcmp(buf, "exit")) {
			break;
		}

		fixtoken_test(buf, " ");
	}
	return 0;
}


