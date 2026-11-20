/*
 * libFuzzer harness for pglogical: runs a PostgreSQL backend in-process (the same startup the
 * single-user `postgres --single` path does: PostgresSingleUserMain + the init half of
 * PostgresMain), with pglogical initialized as from shared_preload_libraries, and drives pglogical through its
 * public SQL interface.
 *
 * Fuzz inputs never become SQL text: every statement is a fixed template and the fuzz bytes are
 * bound as text parameters (SPI_execute_with_args), so no escaping is involved.
 *
 * Input layout (output/funcs modes): byte 0 selects a template, the rest is split on '\n' into
 * text values. PGL_MODE_APPLY (fuzz_apply_proto) takes a stream of native protocol messages
 * instead; it is described with its code at the end of this file.
 *
 *   PGL_MODE_OUTPUT  (fuzz_output_params) — the pglogical_output plugin's startup parameters, as a
 *       replication client sends them: pg_logical_slot_peek[_binary]_changes('s', NULL, NULL,
 *       VARIADIC <values>) on a slot created with plugin pglogical_output over prepared WAL
 *       (inserts/updates/deletes/queued DDL). Reaches pg_decode_startup, process_parameters_v1,
 *       the hooks/repset filtering and the native/JSON protocol writers.
 *   PGL_MODE_FUNCS   (fuzz_sql_functions) — text arguments of the pglogical.* SQL functions
 *       (row filters, dsns, replication-set and node names, column lists).
 *   PGL_MODE_APPLY   (fuzz_apply_proto) — the native replication protocol stream an apply worker
 *       receives from the upstream node: pglogical_read_insert/update/delete/tuple and the heap
 *       apply functions.
 *
 * Per-input isolation: each input runs in its own transaction that is always rolled back; the
 * slot is only peeked (never advanced), so every input sees the same database. Errors raised by
 * PostgreSQL (ereport(ERROR)) are the backend's normal way to reject an input: they are caught
 * with PG_TRY, the PostgreSQL API for this, and the transaction is aborted exactly as the
 * backend's main loop does. Assertion failures (the backend is built with --enable-cassert) and
 * sanitizer reports are crashes.
 */
#include "postgres.h"

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "access/xact.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/postmaster.h"
#include "replication/slot.h"
#include "storage/ipc.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/timeout.h"
#include "utils/timestamp.h"
#include "utils/snapmgr.h"
#include "access/xlog.h"
#include "storage/pg_shmem.h"
#include "utils/ps_status.h"

/* pglogical's module initializer (pglogical.c), linked into this binary */
extern void _PG_init(void);

/* defined by src/backend/main/main.c, which this binary replaces */
const char *progname = "postgres";

#define FUZZ_ROLE "fuzz"
#define FUZZ_DB "postgres"
#define MAX_VALUES 32

static char datadir[1024];

static void
die_setup(const char *what)
{
	fprintf(stderr, "pgl_fuzz: setup failed: %s\n", what);
	abort();
}

#ifndef PGL_FUZZ_ROOT
#define PGL_FUZZ_ROOT "/mayhem/mayhem/out/fuzz"
#endif

/* the staged install tree build.sh made: bin/ lib/ share/ data-template/ */
static char fuzz_root[1024];
/* the executable path handed to PostgreSQL, which finds lib/ and share/ relative to it */
static char pg_exec[1200];

static int
is_root(const char *dir)
{
	char		tmpl[1200];

	snprintf(tmpl, sizeof(tmpl), "%s/data-template/PG_VERSION", dir);
	return access(tmpl, R_OK) == 0;
}

/* rm -rf without spawning a process (no symlinks are followed: lstat + unlink) */
static void
rm_tree(const char *dir)
{
	DIR		   *d = opendir(dir);
	struct dirent *de;

	if (d != NULL)
	{
		while ((de = readdir(d)) != NULL)
		{
			char		path[2048];
			struct stat st;

			if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
				continue;
			snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
			if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
				rm_tree(path);
			else
				unlink(path);
		}
		closedir(d);
	}
	rmdir(dir);
}

/* atexit: every process copies the ~20 MB template, so never leave the copy behind */
static void
remove_datadir(void)
{
	if (datadir[0] != '\0' && getpid() == MyProcPid)
		rm_tree(datadir);
}

/*
 * Copies left by processes that died without running atexit (a crash, a timeout kill): remove
 * those whose owning process (the pid in postmaster.pid, which PostgreSQL writes at startup) is
 * gone, or that never got that far and are older than ten minutes.
 */
static void
sweep_stale(const char *tmp)
{
	DIR		   *d = opendir(tmp);
	struct dirent *de;

	if (d == NULL)
		return;
	while ((de = readdir(d)) != NULL)
	{
		char		dir[1200];
		char		pidfile[1300];
		struct stat st;
		FILE	   *f;
		long		pid = 0;
		int			stale;

		if (strncmp(de->d_name, "pgl_fuzz.", 9) != 0)
			continue;
		snprintf(dir, sizeof(dir), "%s/%s", tmp, de->d_name);
		if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid())
			continue;
		snprintf(pidfile, sizeof(pidfile), "%s/postmaster.pid", dir);
		if ((f = fopen(pidfile, "r")) != NULL)
		{
			/* a single-user backend writes its pid negated */
			if (fscanf(f, "%ld", &pid) != 1)
				pid = 0;
			if (pid < 0)
				pid = -pid;
			fclose(f);
		}
		if (pid > 0)
			stale = kill((pid_t) pid, 0) != 0 && errno == ESRCH;
		else
			stale = time(NULL) - st.st_mtime > 600;
		if (stale)
			rm_tree(dir);
	}
	closedir(d);
}

/* cp -r without spawning a process: directories 0700, regular files 0600 (what PostgreSQL wants) */
static void
copy_tree(const char *src, const char *dst)
{
	DIR		   *d = opendir(src);
	struct dirent *de;

	if (d == NULL)
		die_setup(src);
	if (mkdir(dst, 0700) != 0 && errno != EEXIST)
		die_setup(dst);
	while ((de = readdir(d)) != NULL)
	{
		char		s[2048];
		char		t[2048];
		struct stat st;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		snprintf(s, sizeof(s), "%s/%s", src, de->d_name);
		snprintf(t, sizeof(t), "%s/%s", dst, de->d_name);
		if (lstat(s, &st) != 0)
			die_setup(s);
		if (S_ISDIR(st.st_mode))
			copy_tree(s, t);
		else if (S_ISREG(st.st_mode))
		{
			char		buf[65536];
			ssize_t		n;
			int			in = open(s, O_RDONLY);
			int			out = open(t, O_WRONLY | O_CREAT | O_TRUNC, 0600);

			if (in < 0 || out < 0)
				die_setup(s);
			while ((n = read(in, buf, sizeof(buf))) > 0)
				if (write(out, buf, n) != n)
					die_setup(t);
			if (n < 0)
				die_setup(s);
			close(in);
			close(out);
		}
	}
	closedir(d);
}

/*
 * Find the install tree and copy its template data directory to a private scratch directory.
 * The tree is located from /proc/self/exe (<root>/bin/<harness>), falling back to the absolute
 * install path baked in at build time, so it does not depend on argv[0] or on where a fuzzer
 * runs (or copies) the binary from.
 */
static void
make_datadir(void)
{
	char		exe[1024];
	static char cwdbuf[1024];
	const char *tmp = getenv("TMPDIR");
	ssize_t		n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

	fuzz_root[0] = '\0';
	if (n > 0)
	{
		char	   *slash;

		exe[n] = '\0';
		if ((slash = strrchr(exe, '/')) != NULL)
		{
			*slash = '\0';
			snprintf(fuzz_root, sizeof(fuzz_root), "%s/..", exe);
			if (!is_root(fuzz_root))
				fuzz_root[0] = '\0';
		}
	}
	if (fuzz_root[0] == '\0')
	{
		snprintf(fuzz_root, sizeof(fuzz_root), "%s", PGL_FUZZ_ROOT);
		if (!is_root(fuzz_root))
			die_setup("cannot find the staged install tree (data-template)");
	}
	snprintf(pg_exec, sizeof(pg_exec), "%s/bin/postgres", fuzz_root);

	/*
	 * Scratch location: $TMPDIR, then /tmp (both writable under Mayhem, SPEC 6.2 item 13), and
	 * only as a last resort the working directory. The working directory is the fuzzer's own
	 * area (Mayhem stages test cases and collects outputs there), so a ~27 MB private data
	 * directory of 0700/0600 files must not be dropped into it.
	 */
	if (tmp != NULL && *tmp != '\0' && access(tmp, W_OK | X_OK) == 0)
		;
	else if (access("/tmp", W_OK | X_OK) == 0)
		tmp = "/tmp";
	else if (getcwd(cwdbuf, sizeof(cwdbuf)) != NULL && access(cwdbuf, W_OK | X_OK) == 0)
		tmp = cwdbuf;
	else
		die_setup("no writable scratch directory ($TMPDIR, /tmp, cwd)");
	sweep_stale(tmp);
	snprintf(datadir, sizeof(datadir), "%s/pgl_fuzz.XXXXXX", tmp);
	if (mkdtemp(datadir) == NULL)
		die_setup("mkdtemp");
	MyProcPid = getpid();
	atexit(remove_datadir);
	{
		char		tmpl[1200];

		snprintf(tmpl, sizeof(tmpl), "%s/data-template", fuzz_root);
		copy_tree(tmpl, datadir);
	}
}

static void
run_setup_sql(const char *sql)
{
	StartTransactionCommand();
	PushActiveSnapshot(GetTransactionSnapshot());
	if (SPI_connect() != SPI_OK_CONNECT)
		die_setup("SPI_connect");
	if (SPI_execute(sql, false, 0) < 0)
		die_setup(sql);
	SPI_finish();
	PopActiveSnapshot();
	CommitTransactionCommand();
}

/*
 * While the backend is being set up, a FATAL (or PANIC) report would make PostgreSQL exit(1)
 * quietly; turn it into an abort with the message on stderr, so a setup failure in any runtime
 * environment is a visible crash with a backtrace, never a silent exit.
 */
static bool in_setup = true;

static void
setup_fatal_hook(ErrorData *edata)
{
	if (in_setup && edata->elevel >= FATAL)
	{
		fprintf(stderr, "pgl_fuzz: setup failed: %s\n", edata->message ? edata->message : "?");
		abort();
	}
}

static void
start_backend(void)
{
	char	   *pargv[64];
	int			pargc = 0;

	setlocale(LC_ALL, "C");
	unsetenv("LC_ALL");
	MyProcPid = getpid();
	MemoryContextInit();
	emit_log_hook = setup_fatal_hook;
	/* no client: reports go to the server log only (which log_min_messages filters) */
	whereToSendOutput = DestNone;

	InitStandaloneProcess(pg_exec);
	InitializeGUCOptions();

	pargv[pargc++] = "postgres";
#define OPT(s) do { pargv[pargc++] = "-c"; pargv[pargc++] = (s); } while (0)
	OPT("output_plugin_libraries=pgoutput,test_decoding,pglogical_output");
	OPT("wal_level=logical");
	OPT("max_replication_slots=4");
	OPT("max_wal_senders=4");
	OPT("max_worker_processes=8");
	OPT("shared_buffers=16MB");
	OPT("fsync=off");
	OPT("synchronous_commit=off");
	OPT("dynamic_shared_memory_type=mmap");
	/*
	 * Silent from the start: nothing but libFuzzer's own lines on stdout/stderr (Mayhem fails the
	 * whole run with an internal error when backend LOG/DETAIL/CONTEXT lines precede them).
	 * A FATAL during setup still reaches setup_fatal_hook. PGL_FUZZ_DEBUG=1 keeps ERRORs.
	 */
	OPT(getenv("PGL_FUZZ_DEBUG") ? "log_min_messages=error" : "log_min_messages=fatal");
	OPT("client_min_messages=error");
	OPT("pglogical.synchronous_commit=off");
#undef OPT
	pargv[pargc] = NULL;
	process_postgres_switches(pargc, pargv, PGC_POSTMASTER, NULL);

	if (!SelectConfigFiles(datadir, progname))
		die_setup("SelectConfigFiles");
	checkDataDir();
	ChangeToDataDir();
	CreateDataDirLockFile(false);
	LocalProcessControlFile(false);
	/*
	 * pglogical is linked into this binary (see build.sh), so run its _PG_init here, exactly where
	 * shared_preload_libraries=pglogical would have dlopen'ed it and run it.
	 */
	process_shared_preload_libraries_in_progress = true;
	_PG_init();
	process_shared_preload_libraries_in_progress = false;
	process_shared_preload_libraries();
	InitializeMaxBackends();
	process_shmem_requests();
	InitializeShmemGUCs();
	InitializeWalConsistencyChecking();
	CreateSharedMemoryAndSemaphores();
	PgStartTime = GetCurrentTimestamp();
	InitProcess();

	/* the init half of PostgresMain() */
	SetProcessingMode(InitProcessing);
	InitializeTimeouts();
	pqsignal(SIGPIPE, SIG_IGN);
	BaseInit();
	sigprocmask(SIG_SETMASK, &UnBlockSig, NULL);
	InitPostgres(FUZZ_DB, InvalidOid, FUZZ_ROLE, InvalidOid, 0, NULL);
	if (PostmasterContext)
	{
		MemoryContextDelete(PostmasterContext);
		PostmasterContext = NULL;
	}
	SetProcessingMode(NormalProcessing);
	whereToSendOutput = DestNone;
	/* PostgresMain's per-message context; pglogical's DDL execution allocates in it */
	MessageContext = AllocSetContextCreate(TopMemoryContext, "MessageContext",
										   ALLOCSET_DEFAULT_SIZES);
}

static void
prepare_database(void)
{
	run_setup_sql("CREATE EXTENSION pglogical");
	run_setup_sql("CREATE TABLE public.t(a int PRIMARY KEY, b text, c numeric, d bytea, "
				  "e int[], f jsonb, g timestamptz, h bool)");
	run_setup_sql("CREATE TABLE public.t2(a int PRIMARY KEY, b text, c int)");
	run_setup_sql("CREATE TABLE public.t3(a int, b text)");
	run_setup_sql("CREATE TABLE public.t5(a int PRIMARY KEY, b text, c int)");
	run_setup_sql("CREATE SEQUENCE public.s1");
	run_setup_sql("SELECT pglogical.create_node('n', 'dbname=" FUZZ_DB "')");
	run_setup_sql("SELECT pglogical.create_replication_set('rs2', true, true, false, true)");
	run_setup_sql("SELECT pglogical.replication_set_add_table('default', 'public.t')");
	/*
	 * No row filter on a decoded table: evaluating one from the SQL decoding interface trips
	 * PostgreSQL's Assert(!FirstSnapshotSet) in GetTransactionSnapshot() on every change, which
	 * would make every input crash the same way (row filters are fuzzed by fuzz_sql_functions).
	 */
	run_setup_sql("SELECT pglogical.replication_set_add_table('rs2', 'public.t2', false, "
				  "ARRAY['a','b'])");
	run_setup_sql("SELECT pglogical.replication_set_add_sequence('default', 'public.s1')");
	run_setup_sql("SELECT pg_create_logical_replication_slot('s', 'pglogical_output')");
	run_setup_sql("INSERT INTO public.t VALUES "
				  "(1, 'one', 1.5, '\\x00ff', '{1,2}', '{\"k\": [1, null]}', '2020-01-01 00:00+00', true), "
				  "(2, NULL, NULL, NULL, NULL, NULL, NULL, NULL)");
	run_setup_sql("UPDATE public.t SET b = 'uno', c = c * 2 WHERE a = 1");
	run_setup_sql("DELETE FROM public.t WHERE a = 2");
	run_setup_sql("INSERT INTO public.t2 SELECT g, 'r' || g, g * 10 FROM generate_series(1, 3) g");
	run_setup_sql("UPDATE public.t2 SET a = a + 10 WHERE a = 3");
	run_setup_sql("SELECT pglogical.replicate_ddl_command('CREATE TABLE public.t4(a int PRIMARY KEY)')");
	run_setup_sql("SELECT nextval('public.s1'), pglogical.synchronize_sequence('public.s1')");
	run_setup_sql("TRUNCATE public.t3");
	/* PGL_FUZZ_DEBUG=1 keeps ERROR reports on stderr (for reproducing an input by hand) */
	if (getenv("PGL_FUZZ_DEBUG") == NULL)
		SetConfigOption("log_min_messages", "fatal", PGC_SUSET, PGC_S_OVERRIDE);
}

/*
 * The backend runs with its data directory as the working directory (PostgreSQL opens every
 * relation and WAL file by a path relative to it), but libFuzzer and the standalone driver only
 * read their arguments after LLVMFuzzerInitialize returns. Rewrite relative paths among the
 * arguments (inputs, corpus dirs, path-valued flags) to absolute ones against the original
 * working directory, so a fuzzer that passes relative paths keeps working. For libFuzzer, crash
 * artifacts also default to the original working directory instead of the scratch datadir.
 */
extern int	LLVMFuzzerRunDriver(int *argc, char ***argv,
								int (*cb) (const uint8_t *data, size_t size)) __attribute__((weak));

static const char *const path_flags[] = {
	"-artifact_prefix=", "-exact_artifact_path=", "-dict=", "-merge_control_file=",
	"-features_dir=", "-data_flow_trace=", "-stop_file=", "-mutation_graph_file=",
	"-seed_inputs=", "-merge_inner=", NULL
};

static char *
abs_path(const char *cwd, const char *prefix, const char *path)
{
	size_t		len = strlen(cwd) + strlen(prefix) + strlen(path) + 3;
	char	   *r = malloc(len);

	if (r == NULL)
		die_setup("malloc");
	if (path[0] == '/' || path[0] == '\0' || cwd[0] == '\0')
		snprintf(r, len, "%s%s", prefix, path);
	else
		snprintf(r, len, "%s%s/%s", prefix, cwd, path);
	return r;
}

static void
absolutize_args(int *argc, char ***argv)
{
	char		cwd[1024];
	char	  **nargv = malloc(sizeof(char *) * (*argc + 2));
	int			nargc = 0;
	int			have_artifact_prefix = 0;

	if (nargv == NULL)
		die_setup("malloc");
	if (getcwd(cwd, sizeof(cwd)) == NULL)
		cwd[0] = '\0';
	nargv[nargc++] = (*argv)[0];
	for (int i = 1; i < *argc; i++)
	{
		char	   *a = (*argv)[i];
		char	   *out = a;

		if (a[0] == '-')
		{
			for (int f = 0; path_flags[f] != NULL; f++)
			{
				size_t		fl = strlen(path_flags[f]);

				if (strncmp(a, path_flags[f], fl) != 0)
					continue;
				if (f == 0)
					have_artifact_prefix = 1;
				/* -seed_inputs=a,b,c or -seed_inputs=@listfile: only a lone path is rewritten */
				if (strcmp(path_flags[f], "-seed_inputs=") == 0 && strchr(a + fl, ',') != NULL)
					break;
				if (a[fl] == '@')
				{
					char		pre[64];

					snprintf(pre, sizeof(pre), "%s@", path_flags[f]);
					out = abs_path(cwd, pre, a + fl + 1);
				}
				else
				{
					char		pre[64];

					snprintf(pre, sizeof(pre), "%s", path_flags[f]);
					out = abs_path(cwd, pre, a + fl);
				}
				break;
			}
		}
		else
			out = abs_path(cwd, "", a);
		nargv[nargc++] = out;
	}
	if (LLVMFuzzerRunDriver != NULL && !have_artifact_prefix && cwd[0] != '\0')
	{
		/* artifacts are written as <cwd>/crash-<sha1>, not into the scratch datadir */
		size_t		l = strlen(cwd) + sizeof("-artifact_prefix=/");
		char	   *r = malloc(l);

		if (r == NULL)
			die_setup("malloc");
		snprintf(r, l, "-artifact_prefix=%s/", cwd);
		nargv[nargc++] = r;
	}
	nargv[nargc] = NULL;
	*argc = nargc;
	*argv = nargv;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	/*
	 * PostgreSQL's checkDataDir() sets the process umask to 077 (pg_mode_mask) for its own data
	 * files. Restore the caller's umask once the backend is up, so the files the fuzzer itself
	 * writes (corpus entries, crash artifacts) keep their normal permissions: under 077 they are
	 * owner-only, which Mayhem cannot read back, and every run failed with an internal error.
	 * The backend creates its files with explicit modes (pg_file_create_mode), so it is unaffected.
	 */
	mode_t		saved_umask = umask(022);

	umask(saved_umask);
	absolutize_args(argc, argv);
	make_datadir();
	start_backend();
	prepare_database();
	in_setup = false;
	emit_log_hook = NULL;
	umask(saved_umask);
	return 0;
}

#if defined(PGL_MODE_APPLY)
/* see the PGL_MODE_APPLY section at the end of this file */
#elif defined(PGL_MODE_OUTPUT)
static const char *const templates[] = {
	"SELECT count(*) FROM pg_logical_slot_peek_changes('s', NULL, NULL, VARIADIC $1)",
	"SELECT count(*) FROM pg_logical_slot_peek_binary_changes('s', NULL, NULL, VARIADIC $1)",
};
#define TEMPLATE_ARRAY_ARG 1	/* all values go into one text[] parameter */
#elif defined(PGL_MODE_FUNCS)
static const char *const templates[] = {
	"SELECT pglogical.replication_set_add_table('default', 'public.t2'::regclass, false, NULL, $1)",
	"SELECT pglogical.replication_set_add_table('rs2', 'public.t5'::regclass, true, ARRAY[$1, $2], $3)",
	"SELECT pglogical.alter_node_add_interface('n', $1, $2)",
	"SELECT pglogical.create_replication_set($1)",
	"SELECT count(*) FROM pglogical.show_repset_table_info('public.t2'::regclass, ARRAY[$1, $2])",
	"SELECT count(*) FROM pglogical.table_data_filtered(NULL::public.t2, 'public.t2'::regclass, ARRAY[$1, $2])",
	"SELECT pglogical.replication_set_add_all_tables($1, ARRAY[$2])",
	"SELECT pglogical.pglogical_gen_slot_name($1, $2, $3)",
	"SELECT pglogical.alter_replication_set($1, true, false, true, false)",
	"SELECT pglogical.replication_set_remove_table($1, 'public.t'::regclass)",
	"SELECT pglogical.drop_node($1, true)",
	"SELECT pglogical.alter_node_drop_interface($1, $2)",
};
#define TEMPLATE_ARRAY_ARG 0	/* value i is bound to $i+1 */
#else
#error "define PGL_MODE_OUTPUT, PGL_MODE_FUNCS or PGL_MODE_APPLY"
#endif
#ifndef PGL_MODE_APPLY
#define NTEMPLATES (sizeof(templates) / sizeof(templates[0]))

static int
count_params(const char *q)
{
	int			n = 0;

	for (const char *p = q; (p = strchr(p, '$')) != NULL; p++)
		if (p[1] - '0' > n)
			n = p[1] - '0';
	return n;
}

static void
run_one(const char *query, int nvalues, char **values)
{
	Oid			argtypes[MAX_VALUES];
	Datum		args[MAX_VALUES];
	char		nulls[MAX_VALUES];
	int			nargs;

	if (TEMPLATE_ARRAY_ARG)
	{
		Datum	   *elems = palloc(sizeof(Datum) * (nvalues + 1));

		for (int i = 0; i < nvalues; i++)
			elems[i] = CStringGetTextDatum(values[i]);
		argtypes[0] = TEXTARRAYOID;
		args[0] = PointerGetDatum(construct_array_builtin(elems, nvalues, TEXTOID));
		nulls[0] = ' ';
		nargs = 1;
	}
	else
	{
		nargs = count_params(query);
		for (int i = 0; i < nargs; i++)
		{
			argtypes[i] = TEXTOID;
			if (i < nvalues)
			{
				args[i] = CStringGetTextDatum(values[i]);
				nulls[i] = ' ';
			}
			else
			{
				args[i] = (Datum) 0;
				nulls[i] = 'n';
			}
		}
	}

	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "SPI_connect failed");
	SPI_execute_with_args(query, nargs, argtypes, args, nulls, false, 0);
	SPI_finish();
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char	   *buf;
	char	   *values[MAX_VALUES];
	int			nvalues = 0;
	const char *query;
	MemoryContext fuzzcxt;
	MemoryContext oldcxt;

	if (size < 1)
		return -1;
	query = templates[data[0] % NTEMPLATES];
	MemoryContextReset(MessageContext);

	fuzzcxt = AllocSetContextCreate(TopMemoryContext, "fuzz input", ALLOCSET_DEFAULT_SIZES);
	oldcxt = MemoryContextSwitchTo(fuzzcxt);

	/* text values cannot hold NUL; the database is SQL_ASCII, so any other byte is valid */
	buf = palloc(size);
	memcpy(buf, data + 1, size - 1);
	buf[size - 1] = '\0';
	for (size_t i = 0; i + 1 < size; i++)
		if (buf[i] == '\0')
			buf[i] = ' ';
	for (char *p = buf; nvalues < MAX_VALUES;)
	{
		char	   *nl = strchr(p, '\n');

		values[nvalues++] = p;
		if (nl == NULL)
			break;
		*nl = '\0';
		p = nl + 1;
	}

	PG_TRY();
	{
		StartTransactionCommand();
		PushActiveSnapshot(GetTransactionSnapshot());
		run_one(query, nvalues, values);
		PopActiveSnapshot();
		AbortCurrentTransaction();
	}
	PG_CATCH();
	{
		/* the error recovery of PostgresMain()'s main loop */
		HOLD_INTERRUPTS();
		EmitErrorReport();		/* goes nowhere unless PGL_FUZZ_DEBUG is set */
		QueryCancelPending = false;
		AbortCurrentTransaction();
		if (MyReplicationSlot != NULL)
			ReplicationSlotRelease();
		ReplicationSlotCleanup(false);
		MemoryContextSwitchTo(TopMemoryContext);
		FlushErrorState();
		RESUME_INTERRUPTS();
	}
	PG_END_TRY();

	MemoryContextSwitchTo(oldcxt);
	MemoryContextDelete(fuzzcxt);
	return 0;
}
#endif							/* !PGL_MODE_APPLY */

#if defined(PGL_MODE_APPLY)
/*
 * PGL_MODE_APPLY (fuzz_apply_proto) — the native protocol stream a subscriber's apply worker
 * receives from the upstream node (the CopyData payloads apply_work() hands to
 * replication_handler()), read with pglogical's own readers (pglogical_proto_native.c) and
 * applied with its heap apply API (pglogical_apply_heap.c), as handle_insert/update/delete do.
 * Neither the readers nor the heap apply functions use the apply worker or subscription state
 * (MyApplyWorker, MySubscription), so they run in this backend as they do in the worker.
 *
 * Input: a sequence of messages, each <type byte><uint16 big-endian length><body>; a length past
 * the end of the input takes the rest. 'B' begin, 'C' commit, 'O' origin, 'I' insert,
 * 'U' update, 'D' delete; any other type ends the stream (replication_handler errors on it).
 *
 * The remote relation map ('R' messages) is fixed: before every input the harness feeds
 * pglogical_read_rel four 'R' messages built here (remote ids 1-4 naming public.t, public.t2,
 * public.t3 with its columns reordered, public.t5 with a column missing). pglogical's relation
 * cache keeps entries for the life of the backend and has no way to remove one, so fuzzed 'R'
 * messages would carry state from one input to the next; re-sending the fixed ones resets every
 * entry an input can reach (relcache_free_entry clears the cached Relation and mapping).
 * Everything an input changes in the database is rolled back with its transaction.
 */
#include "libpq/pqformat.h"
#include "pglogical_proto_native.h"
#include "pglogical_relcache.h"
#include "pglogical_apply_heap.h"

#define MAX_MESSAGES 64

static const char *const fixed_rels[][10] = {
	{"public", "t", "a", "b", "c", "d", "e", "f", "g", "h"},
	{"public", "t2", "a", "b", "c", NULL},
	{"public", "t3", "b", "a", NULL},
	{"public", "t5", "c", "a", NULL},
};
#define NFIXED_RELS (sizeof(fixed_rels) / sizeof(fixed_rels[0]))
static StringInfoData rel_msgs[NFIXED_RELS];

/* an 'R' body exactly as pglogical_write_rel() sends it (names carry their NUL) */
static void
build_rel_messages(void)
{
	MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);

	for (int r = 0; r < (int) NFIXED_RELS; r++)
	{
		StringInfo	m = &rel_msgs[r];
		int			natts = 0;

		while (natts < 8 && fixed_rels[r][2 + natts] != NULL)
			natts++;
		initStringInfo(m);
		pq_sendbyte(m, 0);		/* flags */
		pq_sendint32(m, r + 1);	/* remote relid */
		pq_sendbyte(m, strlen(fixed_rels[r][0]) + 1);
		pq_sendbytes(m, fixed_rels[r][0], strlen(fixed_rels[r][0]) + 1);
		pq_sendbyte(m, strlen(fixed_rels[r][1]) + 1);
		pq_sendbytes(m, fixed_rels[r][1], strlen(fixed_rels[r][1]) + 1);
		pq_sendbyte(m, 'A');
		pq_sendint16(m, natts);
		for (int i = 0; i < natts; i++)
		{
			const char *n = fixed_rels[r][2 + i];

			pq_sendbyte(m, 'C');
			pq_sendbyte(m, 0);
			pq_sendbyte(m, 'N');
			pq_sendint16(m, strlen(n) + 1);
			pq_sendbytes(m, n, strlen(n) + 1);
		}
	}
	MemoryContextSwitchTo(old);
}

static void
apply_messages(const uint8_t *data, size_t size)
{
	PGLogicalTupleData *oldtup = palloc0(sizeof(PGLogicalTupleData));
	PGLogicalTupleData *newtup = palloc0(sizeof(PGLogicalTupleData));
	size_t		pos = 0;

	for (int r = 0; r < (int) NFIXED_RELS; r++)
	{
		rel_msgs[r].cursor = 0;
		pglogical_read_rel(&rel_msgs[r]);
	}

	for (int n = 0; n < MAX_MESSAGES && pos + 3 <= size; n++)
	{
		char		type = (char) data[pos];
		size_t		len = ((size_t) data[pos + 1] << 8) | data[pos + 2];
		StringInfoData s;
		PGLogicalRelation *rel;
		XLogRecPtr	lsn1,
					lsn2;
		TimestampTz ts;
		TransactionId xid;
		bool		hasold;

		pos += 3;
		if (len > size - pos)
			len = size - pos;
		/* a StringInfo the way the copy stream delivers one: NUL-terminated, cursor 0 */
		initStringInfo(&s);
		appendBinaryStringInfo(&s, (const char *) data + pos, (int) len);
		pos += len;

		switch (type)
		{
			case 'B':
				pglogical_read_begin(&s, &lsn1, &ts, &xid);
				break;
			case 'C':
				pglogical_read_commit(&s, &lsn1, &lsn2, &ts);
				break;
			case 'O':
				(void) pglogical_read_origin(&s, &lsn1);
				break;
			case 'I':
				rel = pglogical_read_insert(&s, RowExclusiveLock, newtup);
				pglogical_apply_heap_insert(rel, newtup);
				pglogical_relation_close(rel, NoLock);
				break;
			case 'U':
				rel = pglogical_read_update(&s, RowExclusiveLock, &hasold, oldtup, newtup);
				pglogical_apply_heap_update(rel, hasold ? oldtup : newtup, newtup);
				pglogical_relation_close(rel, NoLock);
				break;
			case 'D':
				rel = pglogical_read_delete(&s, RowExclusiveLock, oldtup);
				pglogical_apply_heap_delete(rel, oldtup);
				pglogical_relation_close(rel, NoLock);
				break;
			default:
				return;
		}
		CommandCounterIncrement();
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	MemoryContext fuzzcxt;
	MemoryContext oldcxt;

	if (size < 3)
		return -1;
	if (rel_msgs[0].data == NULL)
		build_rel_messages();
	MemoryContextReset(MessageContext);

	fuzzcxt = AllocSetContextCreate(TopMemoryContext, "fuzz input", ALLOCSET_DEFAULT_SIZES);
	oldcxt = MemoryContextSwitchTo(fuzzcxt);

	PG_TRY();
	{
		StartTransactionCommand();
		PushActiveSnapshot(GetTransactionSnapshot());
		MemoryContextSwitchTo(fuzzcxt);
		apply_messages(data, size);
		PopActiveSnapshot();
		AbortCurrentTransaction();
	}
	PG_CATCH();
	{
		/* the error recovery of PostgresMain()'s main loop */
		HOLD_INTERRUPTS();
		EmitErrorReport();		/* goes nowhere unless PGL_FUZZ_DEBUG is set */
		QueryCancelPending = false;
		AbortCurrentTransaction();
		MemoryContextSwitchTo(TopMemoryContext);
		FlushErrorState();
		RESUME_INTERRUPTS();
	}
	PG_END_TRY();

	MemoryContextSwitchTo(oldcxt);
	MemoryContextDelete(fuzzcxt);
	return 0;
}
#endif							/* PGL_MODE_APPLY */
