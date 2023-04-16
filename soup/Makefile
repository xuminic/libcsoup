
CFLAGS	+= -I..

#SRCS	:= $(shell echo *.c)
SRCS	:= csc_bmem.c		\
	   csc_cdll.c		\
	   csc_config.c		\
	   csc_crc16.c		\
	   csc_crc16c.c		\
	   csc_crc32.c		\
	   csc_crc8.c		\
	   csc_cuttoken.c	\
	   csc_dmem.c		\
	   csc_extname_filter.c \
	   csc_file_load.c	\
	   csc_file_store.c	\
	   csc_pack_hex.c	\
	   csc_path_basename.c	\
	   csc_path_path.c	\
	   csc_fixtoken.c	\
	   csc_gettoken.c	\
	   csc_htm_com_pick.c	\
	   csc_htm_doc_pick.c	\
	   csc_htm_tag_pick.c	\
	   csc_isdelim.c	\
	   csc_iso639.c		\
	   csc_memdump.c	\
	   csc_memcpy.c		\
	   csc_strbival.c	\
	   csc_strbody.c	\
	   csc_strchr.c		\
	   csc_strcount_char.c	\
	   csc_strcount_str.c	\
	   csc_strcpy_alloc.c	\
	   csc_strfill.c	\
	   csc_strinsert.c	\
	   csc_strlcat.c	\
	   csc_strlcmp.c	\
	   csc_strlcpy.c	\
	   csc_strrcmp.c	\
	   csc_strrpch.c	\
	   csc_strstr.c		\
	   csc_tmem.c		\
	   csc_token_pick.c	\
	   csc_token_tail.c	\
	   csc_trim_body.c	\
	   csc_trim_head.c	\
	   csc_trim_tail.c	\
	   csc_url_amper.c	\
	   csc_url_decode.c	\
	   csc_ziptoken.c

OBJS	:= $(SRCS:.c=.o)

.PHONY: all clean
	
all: $(OBJS)

clean:
	$(RM) $(OBJS)



