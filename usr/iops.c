#include "includeme.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NR_THREADS 		1
#define NR_REQ_PER_THREAD	100000ULL
#define EXCACHE_SIZE		4096ULL

#define	STORAGE_IOPS

static struct pcache_stat pstat;
static unsigned long pcache_size;
static size_t buf_size, stride;
int fd;

double IOPS[NR_THREADS];
double read_IOPS[NR_THREADS];
double write_IOPS[NR_THREADS];

void print_pstat(struct pcache_stat *pstat)
{
	printf("ExCache Config:\n"
		"   Way: %lu\n"
		"   nr_cachelines: %lu\n"
		"   nr_cachesets: %lu\n"
		"   stride: %#lx\n"
		"   line_size: %#lx\n"
		"   total_size: %#lx\n\n",
		pstat->associativity,
		pstat->nr_cachelines, pstat->nr_cachesets,
		pstat->way_stride, pstat->cacheline_size,
		pcache_size);
}

struct info {
	void *buf;
	int i;

	/*
	 * Use to do random read/write, within a boundary
	 *
	 * file_offset_base ------ file_offset_base+stide
	 */
	size_t file_offset_base;
};

char file_buf[NR_THREADS][EXCACHE_SIZE];

/*
 * Each thread get its own buffer to play with.
 */
static void *thread_func(void *arg)
{
	struct info *info = arg;
	void *buf = info->buf;
	long i, nr_pages;
	struct timeval ts, te, result;
	double usec, iops;

	//printf("%s(): buf: %#lx stride: %#lx REQ_SIZE: %#lx\n",
	//	__func__, buf, stride, NR_REQ_PER_THREAD * EXCACHE_SIZE);

#ifndef STORAGE_IOPS
	gettimeofday(&ts, NULL);
	for (i = 0; i < NR_REQ_PER_THREAD; i++) {
		int *bar;

		bar = buf + EXCACHE_SIZE * i;
		*bar = 100;
	}
	gettimeofday(&te, NULL);
	timeval_sub(&result, &te, &ts);

	usec = result.tv_sec * 1000 * 1000 + result.tv_usec;
	iops =  NR_REQ_PER_THREAD / usec * 1000000;
	IOPS[info->i] = iops;

	//printf("SEQ[%d] NR_REQS: %lu, total runtime [%ld.%ld (s)] IOPS: %lf\n",
	//	info->i, NR_REQ_PER_THREAD, result.tv_sec, result.tv_usec/1000, iops);

#else
	/* Seq Write */
	gettimeofday(&ts, NULL);
	for (i = 0; i < NR_REQ_PER_THREAD; i++)
		write(fd, file_buf[info->i], EXCACHE_SIZE);
	gettimeofday(&te, NULL);
	timeval_sub(&result, &te, &ts);

	usec = result.tv_sec * 1000 * 1000 + result.tv_usec;
	iops =  NR_REQ_PER_THREAD / usec * 1000000;
	write_IOPS[info->i] = iops;

	/* Seq Read */
	gettimeofday(&ts, NULL);
	for (i = 0; i < NR_REQ_PER_THREAD; i++)
		read(fd, file_buf[info->i], EXCACHE_SIZE);
	gettimeofday(&te, NULL);
	timeval_sub(&result, &te, &ts);

	usec = result.tv_sec * 1000 * 1000 + result.tv_usec;
	iops =  NR_REQ_PER_THREAD / usec * 1000000;
	read_IOPS[info->i] = iops;
#endif
}

int main(void)
{
	int i, ret;
	pthread_t tid[NR_THREADS];
	int nr_threads = NR_THREADS;
	void *buf;
	struct info infos[NR_THREADS];

	double iops, read_iops, write_iops;

	setbuf(stdout, NULL);

	/*
	 * Get and print pcache stat.
	 */
	ret = pcache_stat(&pstat);
	if (ret < 0) {
		/* 256MB, 64-way */
		pstat.nr_cachelines = 65536;
		pstat.nr_cachesets = 1024;
		pstat.associativity = 64;
		pstat.cacheline_size = 4096;
		pstat.way_stride = 0x400000;
	}

	buf_size = NR_REQ_PER_THREAD * NR_THREADS * EXCACHE_SIZE;
	stride = buf_size / nr_threads;
	printf("nr_threads: %d buf_size: %#lx stride: %#lx\n", nr_threads, buf_size, stride);

#ifndef STORAGE_IOPS
	/*
	 * Hook up with file
	 */
	buf = malloc(buf_size);
	if (!buf)
		exit(-1);
#else
	fd = open("/mnt/yilun/twitter_rv.net", O_RDWR);
	if (fd < 0) {
		perror("Open: ");
		exit(-1);
	}
#endif

	for (i = 0; i < nr_threads; i++) {
		infos[i].i = i;
		infos[i].buf = buf + stride * i;
		infos[i].file_offset_base = stride * i;
		ret = pthread_create(&tid[i], NULL, thread_func, &infos[i]);
		if (ret)
			die("fail to create new thread");
	}

	for (i = 0; i < nr_threads; i++) {
		pthread_join(tid[i], NULL);
	}

	for (i = 0, iops = 0; i < nr_threads; i++) {
		iops += IOPS[i];
		write_iops += write_IOPS[i];
		read_iops += read_IOPS[i];
	}
	printf(" %d threads, Total IOPS: %lf avg: %lf. Read IOPS: %lf, Write IOPS: %lf\n",
		nr_threads, iops, iops/nr_threads, read_iops, write_iops);

	printf("main() exit\n");
	return 0;
}
