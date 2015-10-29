
/* gcc -Wall -g -O0 -o pthread_queue_simple pthread_queue_simple.c -lpthread */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>


/****************************************************************************
 * The Facility of the message queue for Pthreads
 ****************************************************************************/
/* https://computing.llnl.gov/tutorials/pthreads/#ConditionVariables
 * http://casatwy.com/pthreadde-ge-chong-tong-bu-ji-zhi.html
 * */
typedef	struct	{
	pthread_mutex_t	lock;
	int	qnumber;	/* number of the message boxes */
	int	qsize;		/* net size of the message boxes */
	int	count;		/* in-used the message boxes */
	int	begin;		/* begin index of the message queue */
	
	/* buffer - loading zone of the message boxe 
	 * length - size of the content in the message boxes */
	struct	msgbox	{
		void	*buffer;	
		int	length;
	} q_list[1];
} thread_msgq_t;


void *thread_msgq_open(int num, int size)
{
	thread_msgq_t	*msgq;
	char	*buf;
	int	i;

	if ((num < 1) || (size < 0)) {
		return NULL;
	}

	i = sizeof(thread_msgq_t) + (sizeof(struct msgbox) + size) * num;
	if ((msgq = malloc(i)) == NULL) {
		return NULL;
	}
	memset(msgq, 0, i);

	pthread_mutex_init(&msgq->lock, NULL);
	msgq->qnumber = num;
	msgq->qsize = size;

	/* initialize the index of the queue*/
	buf = (char*) &msgq->q_list[num];
	for (i = 0; i < num; i++) {
		msgq->q_list[i].buffer = buf;
		buf += size;
	}
	return msgq;
}

int thread_msgq_send(void *qid, void *buf, int len)
{
	thread_msgq_t	*msgq = (thread_msgq_t *) qid;
	int	i;

	if (pthread_mutex_lock(&msgq->lock) != 0) {
		return - EBADFD;	/* File descriptor in bad state */
	}

	if (msgq->count == msgq->qnumber) {
		pthread_mutex_unlock(&msgq->lock);
		return - ENOSPC;	/* queue full */
	}

	/* find the index of the empty slot in the queue */
	i = msgq->begin + msgq->count;
	if (i >= msgq->qnumber) {
		i -= msgq->qnumber;
	}

	/* check the size of the message. */
	if (msgq->qsize == 0) {		/* empty message box is allowed */
		msgq->q_list[i].length = len;
		len = 0;	/* cleared for return value */
	} else if ((buf == NULL) && (len == 0)) {	/* empty message is allowed */
		msgq->q_list[i].length = len;
	} else if (buf == NULL) {
		pthread_mutex_unlock(&msgq->lock);
		return - EINVAL;
	} else if (msgq->qsize >= len) {	/* copy the contents */
		msgq->q_list[i].length = len;
		memcpy(msgq->q_list[i].buffer, buf, len);
	} else {	/* Message too long */
		pthread_mutex_unlock(&msgq->lock);
		return - EMSGSIZE;
	}

	msgq->count++;
	pthread_mutex_unlock(&msgq->lock);
	return len;	/* actually copied length */
}

int thread_msgq_receive(void *qid, void *buf, int len)
{
	thread_msgq_t	*msgq = (thread_msgq_t *) qid;

	if (pthread_mutex_lock(&msgq->lock) != 0) {
		return - EBADFD;	/* File descriptor in bad state */
	}

	if (msgq->count == 0) {
		pthread_mutex_unlock(&msgq->lock);
		return - EAGAIN;	/* Resource temporarily unavailable */
	}

	/* copy the content out of the queue */
	if (msgq->qsize && buf) {
		if (len > msgq->q_list[msgq->begin].length) {
			len = msgq->q_list[msgq->begin].length;
		}
		memcpy(buf, msgq->q_list[msgq->begin].buffer, len);
	}

	/* always return the content size in the message box */
	len = msgq->q_list[msgq->begin].length;

	/* move the index to the next available message box */
	msgq->count--;
	if (++msgq->begin == msgq->qnumber) {
		msgq->begin = 0;
	}
	pthread_mutex_unlock(&msgq->lock);
	return len;	
}

int thread_msgq_close(thread_msgq_t *msgq)
{
	pthread_mutex_destroy(&msgq->lock);
	free(msgq);
	return 0;
}


/****************************************************************************
 * Testing
 ****************************************************************************/

struct	msgbl1	{
	long	mtype;
	char	mtext[512];
};

static	pthread_t	taskid_write, taskid_read;
static	thread_msgq_t	*msgqid;


/****************************************************************************
 * Testing with signal
 ****************************************************************************/

static	FILE	*fin;

static void task_read_break_cb(void *arg)
{
	(void) arg;
	printf("task_read_break_cb: closing\n");
	fclose(fin);
}

static void *task_read_file(void *arg)
{
	struct	msgbl1	msgtty;
	
	if ((fin = fopen((char*)arg, "r")) == NULL) {
		perror((char*)arg);
		return NULL;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_cleanup_push(task_read_break_cb, NULL);

	while (fgets(msgtty.mtext, sizeof(msgtty.mtext), fin) != NULL) {
		if (thread_msgq_send(msgqid, &msgtty, sizeof(msgtty)) < 0) {
			printf("thread_msgq_send: failed\n");
		}
		usleep(100000);
	}
	pthread_cleanup_pop(1);
	return NULL;
}

static void task_write_break_cb(void *arg)
{
	(void) arg;
	printf("task_write_break_cb: do nothing\n");
}

static void *task_write_file(void *arg)
{
	struct	msgbl1	msgtty;
	int	rc;

	(void) arg;
	pthread_cleanup_push(task_write_break_cb, NULL);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	while (1) {
		rc = thread_msgq_receive(msgqid, &msgtty, sizeof(msgtty));
		if (rc == - EAGAIN) {
			usleep(10000);
			continue;
		}
		if (rc < 0) {
			printf("thread_msgq_receive: failed to receive.\n");
		}
		printf("%s", msgtty.mtext);
	}
	pthread_cleanup_pop(1);
	return NULL;
}

static int tqueue_signal_test(char *fname)
{
	if ((msgqid = thread_msgq_open(16, sizeof(struct msgbl1))) == NULL) {
		printf("failed to create the message queue\n");
		return 0;
	}

	pthread_create(&taskid_read, NULL, task_read_file, fname);
	pthread_create(&taskid_write, NULL, task_write_file, NULL);

	pthread_join(taskid_read, NULL);
	pthread_cancel(taskid_write);
	pthread_join(taskid_write, NULL);

	thread_msgq_close(msgqid);
	return 0;
}

/****************************************************************************
 * Testing Main
 ****************************************************************************/

static void signal_close_all(int signo)
{
	printf("\nUser Terminated! [%d]\n", signo);
		
	pthread_cancel(taskid_write);
	pthread_cancel(taskid_read);
}

int main(int argc, char **argv)
{
	struct	sigaction	sact;   

	//install the serial handler before making the device asynchronous
	sact.sa_handler = signal_close_all;
	sact.sa_flags = 0;
	sigaction(SIGINT, &sact, NULL);
	sigaction(SIGHUP, &sact, NULL);
	sigaction(SIGTERM, &sact, NULL);
	sigaction(SIGQUIT, &sact, NULL);
	sigaction(SIGABRT, &sact, NULL);

	if (argc > 1) {
		tqueue_signal_test(argv[1]);
	}
	return 0;
}

