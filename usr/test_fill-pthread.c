#include "includeme.h"
#include <assert.h>
#include <pthread.h>

#define NR_BITS 12
#define SET_MASK ((1ULL << 28) - 1) 

#define RUN_SIZE	(1024*1024*128)
#define NR_THREADS	1

double rand_val(int seed);
int zipf(double alpha, int n);

unsigned long addr2set(unsigned long addr)
{
	return (addr & SET_MASK) >> NR_BITS;
}

void *base;

__thread int nr_run;

void seq_heap_run(void)
{
	int tid = gettid();
	long i, nr_pages;
	struct timeval ts, te, result;

	nr_pages = RUN_SIZE / PAGE_SIZE;

	gettimeofday(&ts, NULL);
	for (i = 0; i < nr_pages; i++) {
		int *bar;

		bar = base + PAGE_SIZE * i;
		*bar = 100;
	}
	gettimeofday(&te, NULL);
	timeval_sub(&result, &te, &ts);

	fprintf(stderr, " %s(nr=%d)(tid=%d)  Total LLC runtime [%ld.%ld (s)] / "
		"nr_pages [%d] (%dMB) ---> LLC_miss_latency [%ld (ns)]\n", __func__,
		nr_run, tid, result.tv_sec, result.tv_usec/1000, nr_pages,
		(nr_pages * PAGE_SIZE)/1024/1024,
		(1000000000*result.tv_sec + 1000*result.tv_usec)/nr_pages);

	nr_run++;
}

static unsigned long *zipf_addresses;
static pthread_spinlock_t zipf_lock;
static pthread_barrier_t zipf_barrier;

static void zipf_run(void)
{
	double alpha;
	int tid = gettid();
	long i, nr_pages;
	struct timeval ts, te, result;

	nr_pages = RUN_SIZE / PAGE_SIZE;

	/* The larger alpha, the better locality */
	alpha = 1;

	zipf_addresses = malloc(sizeof(zipf_addresses) * nr_pages);
	if (!zipf_addresses)
		die("oom");

	/* Generate array */
	fprintf(stderr, "  Generating zipf array... \n");
	pthread_spin_lock(&zipf_lock);
	/* random seed */
	rand_val(1);
	for (i = 0; i < nr_pages; i++) {
		int page_index;

		page_index = zipf(alpha, nr_pages);
		zipf_addresses[i] = (unsigned long)base + (page_index * PAGE_SIZE);

		/* paranoid check */
		if (zipf_addresses[i] > (unsigned long)base + RUN_SIZE) {
			die("bug: %#lx, %#lx", zipf_addresses[i],
				(unsigned long)base + RUN_SIZE);
		}
	}
	pthread_spin_unlock(&zipf_lock);
	fprintf(stderr, "  Generating zipf array... Done\n");

	/* Wait until all threads finish computation */
	pthread_barrier_wait(&zipf_barrier);

	gettimeofday(&ts, NULL);
	for (i = 0; i < nr_pages; i++) {
		unsigned long *bar;

		bar = (unsigned long *)zipf_addresses[i];
		*bar = 100;
	}
	gettimeofday(&te, NULL);
	timeval_sub(&result, &te, &ts);

	fprintf(stderr, " %s(nr=%d)(tid=%d)  Total LLC runtime [%ld.%ld (s)] / "
		"nr_pages [%d] (%dMB) ---> LLC_miss_latency [%ld (ns)]\n", __func__,
		nr_run, tid, result.tv_sec, result.tv_usec/1000, nr_pages,
		(nr_pages * PAGE_SIZE)/1024/1024,
		(1000000000*result.tv_sec + 1000*result.tv_usec)/nr_pages);

	nr_run++;
}

static unsigned long *random_addresses;

static void ran_run(void)
{
	int tid = gettid();
	long i, nr_pages;
	struct timeval ts, te, result;

	srand(time(NULL));

	nr_pages = RUN_SIZE / PAGE_SIZE;

	random_addresses = malloc(sizeof(random_addresses) * nr_pages);
	if (!random_addresses)
		die("oom");

	/* Generate array */
	fprintf(stderr, "  Generating random array... \n");
	for (i = 0; i < nr_pages; i++) {
		int page_index;

		page_index = rand() % nr_pages;
		random_addresses[i] = (unsigned long)base + (page_index * PAGE_SIZE);

		/* paranoid check */
		if (random_addresses[i] > (unsigned long)base + RUN_SIZE) {
			die("bug: %#lx, %#lx", random_addresses[i],
				(unsigned long)base + RUN_SIZE);
		}
	}
	fprintf(stderr, "  Generating random array... Done\n");

	gettimeofday(&ts, NULL);
	for (i = 0; i < nr_pages; i++) {
		unsigned long *bar;

		bar = (unsigned long *)random_addresses[i];
		*bar = 100;
	}
	gettimeofday(&te, NULL);
	timeval_sub(&result, &te, &ts);

	fprintf(stderr, " %s(nr=%d)(tid=%d)  Total LLC runtime [%ld.%ld (s)] / "
		"nr_pages [%d] (%dMB) ---> LLC_miss_latency [%ld (ns)]\n", __func__,
		nr_run, tid, result.tv_sec, result.tv_usec/1000, nr_pages,
		(nr_pages * PAGE_SIZE)/1024/1024,
		(1000000000*result.tv_sec + 1000*result.tv_usec)/nr_pages);

	nr_run++;
}

static void *thread_func(void *arg)
{
	int tid = gettid();

	printf("Thread [%d] running\n", tid);
	seq_heap_run();
	//zipf_run();
	//ran_run();
}

int main(void)
{
	int i, ret;
	pthread_t tid[NR_THREADS];
	int nr_threads = NR_THREADS;

	printf("Configuration: nr_threads=%d, RUN_SIZE: %d MB \n",
		nr_threads, RUN_SIZE/1024/1024);

	/* The heap we are going to touch */
	base = malloc(RUN_SIZE);
	if (!base)
		die("fail to malloc");
	
	pthread_spin_init(&zipf_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_barrier_init(&zipf_barrier, NULL, NR_THREADS);

	for (i = 0; i < nr_threads; i++) {
		ret = pthread_create(&tid[i], NULL, thread_func, NULL);
		if (ret)
			die("fail to create new thread");
	}

	for (i = 0; i < nr_threads; i++) {
		pthread_join(tid[i], NULL);
	}

	printf("main() exit\n");
	free(base);
	return 0;
}

//===========================================================================
//=  Function to generate Zipf (power law) distributed random variables     =
//=    - Input: alpha and N                                                 =
//=    - Output: Returns with Zipf distributed random variable              =
//===========================================================================
int zipf(double alpha, int n)
{
  static int first = 1;      // Static first time flag
  static double c = 0;          // Normalization constant
  double z;                     // Uniform random number (0 < z < 1)
  double sum_prob;              // Sum of probabilities
  double zipf_value=0;            // Computed exponential value to be returned
  int    i;                     // Loop counter

  // Compute normalization constant on first call only
  if (first == 1)
  {
    for (i=1; i<=n; i++)
      c = c + (1.0 / pow((double) i, alpha));
    c = 1.0 / c;
    first = 0;
  }

  // Pull a uniform random number (0 < z < 1)
  do
  {
    z = rand_val(0);
  }
  while ((z == 0) || (z == 1));

  // Map z to the value
  sum_prob = 0;
  for (i=1; i<=n; i++)
  {
    sum_prob = sum_prob + c / pow((double) i, alpha);
    if (sum_prob >= z)
    {
      zipf_value = i;
      break;
    }
  }

  // Assert that zipf_value is between 1 and N
  assert((zipf_value >=1) && (zipf_value <= n));
  //printf("zipf_value: %ld\n", zipf_value);

  return(zipf_value);
}

//=========================================================================
//= Multiplicative LCG for generating uniform(0.0, 1.0) random numbers    =
//=   - x_n = 7^5*x_(n-1)mod(2^31 - 1)                                    =
//=   - With x seeded to 1 the 10000th x value should be 1043618065       =
//=   - From R. Jain, "The Art of Computer Systems Performance Analysis," =
//=     John Wiley & Sons, 1991. (Page 443, Figure 26.2)                  =
//=========================================================================
double rand_val(int seed)
{
  const long  a =      16807;  // Multiplier
  const long  m = 2147483647;  // Modulus
  const long  q =     127773;  // m div a
  const long  r =       2836;  // m mod a
  static long x;               // Random int value
  long        x_div_q;         // x divided by q
  long        x_mod_q;         // x modulo q
  long        x_new;           // New x value

  // Set the seed if argument is non-zero and then return zero
  if (seed > 0)
  {
    x = seed;
    return(0.0);
  }

  // RNG using integer arithmetic
  x_div_q = x / q;
  x_mod_q = x % q;
  x_new = (a * x_mod_q) - (r * x_div_q);
  if (x_new > 0)
    x = x_new;
  else
    x = x_new + m;

  // Return a random value between 0.0 and 1.0
  return((double) x / m);
}
