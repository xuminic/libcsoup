
/* gcc -Wall -g -O0 -o pthread_myq_cancellation pthread_myq_cancellation.c -lpthread */

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
	pthread_cond_t	wait_receive;
	pthread_cond_t	wait_send;
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

#define CSC_MSGQ_BLOCK		NULL
#define CSC_MSGQ_TRY		((void *) -1)

#define CSC_MSGQ_RCODE(x)	(((-1)<<16) | ((short)(x)))
#define CSC_MSGQ_ERRNO(x)	((x) & 0xffff)


thread_msgq_t *thread_msgq_open(int num, int size)
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
	pthread_cond_init(&msgq->wait_receive, NULL);
	pthread_cond_init(&msgq->wait_send, NULL);
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

/* message queue check available mode:
 *   buf: CSC_MSGQ_TRY
 *   len: ignored
 *   return the number of available message boxes in the queue.
 * empty container message queue sending mode:
 *   buf: ignored
 *   len: any data
 *   return 0 if succeed, or < 0 the 16 bit errno
 * normal message queue sending mode:
 *   buf: point to the data
 *   len: length of expecting sending data
 *   return lenght of actually copied data
 */
int thread_msgq_send(thread_msgq_t *msgq, void *buf, int len)
{
	int	i;

	if (pthread_mutex_lock(&msgq->lock) != 0) {
		return CSC_MSGQ_RCODE(EBADFD);	/* File descriptor in bad state */
	}

	/* test queue availability */
	if (buf == CSC_MSGQ_TRY) {
		len = msgq->qnumber - msgq->count;
		pthread_mutex_unlock(&msgq->lock);
		return len;	/* queue available */
	}

	if (msgq->count == msgq->qnumber) {
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(ENOSPC);	/* queue full */
	}

	/* find the index of the empty slot in the queue */
	i = msgq->begin + msgq->count;
	if (i >= msgq->qnumber) {
		i -= msgq->qnumber;
	}

	/* check the size of the message. */
	if (msgq->qsize == 0) {		/* empty message box is allowed */
		msgq->q_list[i].length = len;
		len = 0;	/* cleared for being return value */
	} else if ((buf == NULL) && (len == 0)) {	/* empty message is allowed */
		msgq->q_list[i].length = len;
	} else if (buf == NULL) {
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(EINVAL);
	} else if (msgq->qsize >= len) {	/* copy the contents */
		msgq->q_list[i].length = len;
		memcpy(msgq->q_list[i].buffer, buf, len);
	} else {	/* Message too long */
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(EMSGSIZE);
	}

	msgq->count++;

	if (pthread_cond_signal(&msgq->wait_receive) != 0) {
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(EBADMSG);	/* Bad message */
	}
	pthread_mutex_unlock(&msgq->lock);
	return len;	/* actually copied length */
}

/* message queue check available mode:
 *   buf: CSC_MSGQ_TRY
 *   len: ignored
 *   tmexp: ignored
 *   return the number of available message boxes in the queue.
 * empty container message queue sending mode:
 *   buf: ignored
 *   len: any data
 *   tmexp: wait the specified curtain time if the message queue is full. NULL means indefinite
 *   return 0 if succeed, or < 0 the 16 bit errno
 * normal message queue sending mode:
 *   buf: point to the data
 *   len: length of expecting sending data
 *   tmexp: wait the specified curtain time if the message queue is full. NULL means indefinite
 *   return lenght of actually copied data
 */
int thread_msgq_send_wait(thread_msgq_t *msgq, void *buf, int len,
		struct timespec *tmexp)
{
	struct	timespec	tmnow;
	int	i, rc;

	if ((buf == CSC_MSGQ_TRY) || (tmexp == NULL)) {
		return thread_msgq_send(msgq, buf, len);
	}

	clock_gettime(CLOCK_REALTIME, &tmnow);
	tmnow.tv_sec  += tmexp->tv_sec;
	tmnow.tv_nsec += tmexp->tv_nsec;
	tmnow.tv_sec  += tmnow.tv_nsec / 1000000000;
	tmnow.tv_nsec %= 1000000000;
	
	if (pthread_mutex_lock(&msgq->lock) != 0) {
		return CSC_MSGQ_RCODE(EBADFD);	/* File descriptor in bad state */
	}

	rc = 0;
	while ((msgq->count == msgq->qnumber) && (rc == 0)) {
		rc = pthread_cond_timedwait(&msgq->wait_send, &msgq->lock, &tmnow);
	}
	if (rc != 0) {		/* ETIMEDOUT or errors */
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(rc);
	}

	/* find the index of the empty slot in the queue */
	i = msgq->begin + msgq->count;
	if (i >= msgq->qnumber) {
		i -= msgq->qnumber;
	}

	/* check the size of the message. */
	if (msgq->qsize == 0) {		/* empty message box is allowed */
		msgq->q_list[i].length = len;
		len = 0;	/* cleared for being return value */
	} else if ((buf == NULL) && (len == 0)) {	/* empty message is allowed */
		msgq->q_list[i].length = len;
	} else if (buf == NULL) {
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(EINVAL);
	} else if (msgq->qsize >= len) {	/* copy the contents */
		msgq->q_list[i].length = len;
		memcpy(msgq->q_list[i].buffer, buf, len);
	} else {	/* Message too long */
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(EMSGSIZE);
	}

	msgq->count++;

	if (pthread_cond_signal(&msgq->wait_receive) != 0) {
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(EBADMSG);	/* Bad message */
	}
	pthread_mutex_unlock(&msgq->lock);
	return len;	/* actually copied length */
}


/* message checking mode:
 *   buf: CSC_MSGQ_TRY
 *   len: ignored
 *   return the number of messages in the message queue
 * message receiving mode:
 *   buf: point to the data buffer
 *   len: size of the data buffer
 *   return the length of the message even only part of it been copied into the buffer.
 */
int thread_msgq_receive(thread_msgq_t *msgq, void *buf, int len)
{
	if (pthread_mutex_lock(&msgq->lock) != 0) {
		return CSC_MSGQ_RCODE(EBADFD);	/* File descriptor in bad state */
	}

	/* peep mode doesn't change the message queue counter */
	if (buf == CSC_MSGQ_TRY) {
		len = msgq->count;
		pthread_mutex_unlock(&msgq->lock);
		return len;
	}

	while (msgq->count == 0) {
		if (pthread_cond_wait(&msgq->wait_receive, &msgq->lock) != 0) {
			pthread_mutex_unlock(&msgq->lock);
			return CSC_MSGQ_RCODE(EBADMSG);	/* Bad message */
		}
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
	if (pthread_cond_signal(&msgq->wait_send) != 0) {
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(EBADMSG);	/* Bad message */
	}
	pthread_mutex_unlock(&msgq->lock);
	return len;	
}

/* message checking mode:
 *   buf: CSC_MSGQ_TRY
 *   len: ignored
 *   tmexp: ignored
 *   return the number of messages in the message queue
 * message receiving mode:
 *   buf: point to the data buffer
 *   len: size of the data buffer
 *   tmexp: wait the specified curtain time if the message queue is empty. NULL means indefinite
 *   return the length of the message even only part of it been copied into the buffer.
 */
int thread_msgq_receive_wait(thread_msgq_t *msgq, void *buf, int len, 
		struct timespec *tmexp)
{
	struct	timespec	tmnow;
	int	rc;

	if ((buf == CSC_MSGQ_TRY) || (tmexp == NULL)) {
		return thread_msgq_receive(msgq, buf, len);
	}

	clock_gettime(CLOCK_REALTIME, &tmnow);
	tmnow.tv_sec  += tmexp->tv_sec;
	tmnow.tv_nsec += tmexp->tv_nsec;
	tmnow.tv_sec  += tmnow.tv_nsec / 1000000000;
	tmnow.tv_nsec %= 1000000000;
	
	if (pthread_mutex_lock(&msgq->lock) != 0) {
		return CSC_MSGQ_RCODE(EBADFD);	/* File descriptor in bad state */
	}

	rc = 0;
	while ((msgq->count == 0) && (rc == 0)) {
		rc = pthread_cond_timedwait(&msgq->wait_receive, &msgq->lock, &tmnow);
	}

	if (rc != 0) {		/* ETIMEDOUT or errors */
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(rc);
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
	if (pthread_cond_signal(&msgq->wait_send) != 0) {
		pthread_mutex_unlock(&msgq->lock);
		return CSC_MSGQ_RCODE(EBADMSG);	/* Bad message */
	}
	pthread_mutex_unlock(&msgq->lock);
	return len;	
}

int thread_msgq_close(thread_msgq_t *msgq)
{
	pthread_mutex_destroy(&msgq->lock);
	pthread_cond_destroy(&msgq->wait_receive);
	pthread_cond_destroy(&msgq->wait_send);
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

	(void) arg;
	pthread_cleanup_push(task_write_break_cb, NULL);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	while (1) {
		if (thread_msgq_receive(msgqid, &msgtty, sizeof(msgtty)) < 0) {
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
 * Testing mailbox
 ****************************************************************************/
static int tqueue_onebox_test(void)
{
	void	*msgq;
	int	i, rc;

	if ((msgq = thread_msgq_open(1, 0)) == NULL) {
		printf("failed to create the message queue\n");
		return 0;
	}

	for (i = 0; i < 8; i++) {
		printf("Sending %d\n", i);
		if ((rc = thread_msgq_send(msgq, NULL, i)) < 0) {
			puts(strerror(CSC_MSGQ_ERRNO(rc)));
			if (thread_msgq_receive(msgq, CSC_MSGQ_TRY, 0) > 0) {
				rc = thread_msgq_receive(msgq, NULL, 0);
				printf("Received %d\n", rc);
			}
		}
	}

	for (i = 0; i < 8; i++) {
		if (thread_msgq_send(msgq, CSC_MSGQ_TRY, 0) > 0) {
			printf("Sending %d\n", i);
			thread_msgq_send(msgq, NULL, i);
		} else {
			rc = thread_msgq_receive(msgq, NULL, 0);
			printf("Received %d\n", rc);
			printf("Sending %d\n", i);
			thread_msgq_send(msgq, NULL, i);
		}
	}
	thread_msgq_close(msgq);
	return 0;
}

/****************************************************************************
 * Testing empty send
 ****************************************************************************/
static int tqueue_empty_test(void)
{
	void	*msgq;
	char	buf[32];
	int	rc;

	if ((msgq = thread_msgq_open(4, 16)) == NULL) {
		printf("failed to create the message queue\n");
		return 0;
	}

	thread_msgq_send(msgq, "Hello", 6);
	thread_msgq_send(msgq, "World", 6);
	thread_msgq_send(msgq, NULL, 0);
	thread_msgq_send(msgq, "88", 3);
	
	while (thread_msgq_receive(msgq, CSC_MSGQ_TRY, 0) > 0) {
		rc = thread_msgq_receive(msgq, buf, sizeof(buf));
		if (rc) {
			printf("%s\n", buf);
		} else {
			printf("(%d)\n", rc);
		}
	}

	thread_msgq_close(msgq);
	return 0;
}
	
/****************************************************************************
 * Testing timeout send
 ****************************************************************************/
static int tqueue_timeout_send_test(void)
{
	struct	timespec	tmset;
	void	*msgq;
	int	rc;

	if ((msgq = thread_msgq_open(4, 16)) == NULL) {
		printf("failed to create the message queue\n");
		return 0;
	}

	thread_msgq_send(msgq, "Hello", 6);
	thread_msgq_send(msgq, "World", 6);
	thread_msgq_send(msgq, NULL, 0);
	thread_msgq_send(msgq, "88", 3);

	memset(&tmset, 0, sizeof(tmset));
	tmset.tv_sec = 3;
	rc = thread_msgq_send_wait(msgq, "Byeby", 6, &tmset);
	puts(strerror(CSC_MSGQ_ERRNO(rc)));

	thread_msgq_close(msgq);
	return 0;

}

/****************************************************************************
 * Testing timeout send
 ****************************************************************************/
static void *task_send_wait(void *arg)
{
	struct	timespec	tmset;
	char	buf[16];
	int	i, rc;

	memset(&tmset, 0, sizeof(tmset));
	tmset.tv_sec = 1;
	for (i = 0; i < 10; i++) {
		rc = rand();
		printf("task_send_wait: send %d\n", rc);
		sprintf(buf, "%d", rc);
		if ((rc = thread_msgq_send_wait(msgqid, buf, strlen(buf)+1, &tmset)) < 0) {
			printf("task_send_wait: %s\n", strerror(CSC_MSGQ_ERRNO(rc)));
			sleep(5);
		}
	}
	thread_msgq_send_wait(msgqid, "END", 4, &tmset);
	return 0;
}

static void *task_receive_wait(void *arg)
{
	struct	timespec	tmset;
	char	buf[16];
	int	rc;

	memset(&tmset, 0, sizeof(tmset));
	tmset.tv_sec = 2;

	while (1) {
		printf("task_receive_wait: ready\n");
		if ((rc = thread_msgq_receive_wait(msgqid, buf, 16, &tmset)) < 0) {
			printf("task_receive_wait: %s\n", strerror(CSC_MSGQ_ERRNO(rc)));
			sleep(1);
			continue;
		}
		if (!strcmp(buf, "END")) {
			break;
		}
		printf("task_receive_wait: %s\n", buf);
	}
	return 0;
}

static int tqueue_timeout_test(void)
{
	if ((msgqid = thread_msgq_open(4, 16))  == NULL) {
		printf("failed to create the message queue\n");
		return 0;
	}
	pthread_create(&taskid_read, NULL, task_receive_wait, NULL);
	pthread_create(&taskid_write, NULL, task_send_wait, NULL);

	pthread_join(taskid_read, NULL);
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
	tqueue_onebox_test();
	tqueue_empty_test();
	tqueue_timeout_send_test();
	tqueue_timeout_test();
	return 0;
}

