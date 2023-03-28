#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#include "ipc.h"
#include "server.h"

#define BACKLOG 1000
#define NUM_THREADS 8

#ifndef OUTPUTFILE_TEMPLATE
#define OUTPUTFILE_TEMPLATE "../checker/output/out-XXXXXX"
#endif

int fd;
int ret;

static int lib_prehooks(struct lib *lib)
{
	char *outputfile = malloc(sizeof(OUTPUTFILE_TEMPLATE));
	strcpy(outputfile, OUTPUTFILE_TEMPLATE);
	int fd = mkstemp(outputfile);
	if (fd == -1)
	{
		printf("mkstemp");
		return -1;
	}
	lib->outputfile = outputfile;
	return 0;
}

static int lib_execute(struct lib *lib)
{
	char *error;
	lambda_func_t run;
	setbuf(stdout, NULL);

	int fd = open(lib->outputfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	int backup = dup(STDOUT_FILENO);
	int err = dup2(fd, STDOUT_FILENO);

	void *handle = dlopen(lib->libname, RTLD_NOW | RTLD_GLOBAL);
	if (!handle)
	{
		printf("Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		return -1;
	}

	lib->handle = handle;

	if (lib->funcname == NULL)
	{
		lib->funcname = "run";
	}
	run = dlsym(handle, lib->funcname);

	if (!run)
	{
		printf("Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		return -1;
	}

	if ((error = dlerror()) != NULL)
	{
		fprintf(stderr, "%s\n", error);
		return -1;
	}

	if (lib->filename != NULL)
	{
		lambda_param_func_t p_run = (lambda_param_func_t)run;
		p_run(lib->filename);
	}
	else
	{
		run();
	}

	if (fd == -1)
	{
		printf("open");
		return -1;
	}

	dup2(backup, STDOUT_FILENO);
	close(fd);

	if (err == -1)
	{
		printf("dup");
		return -1;
	}
	return 0;
}

static int lib_close(struct lib *lib)
{

	void *handle = lib->handle;

	int err = dlclose(handle);
	if (err)
	{
		fprintf(stderr, "%s\n", dlerror());
		return -1;
	}
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	return sscanf(buf, "%s %s %s", name, func, params);
}

void *thread_funct(void *arg)
{
	while (1)
	{
		struct lib lib;
		int cfd = accept(fd, NULL, NULL);
		if (cfd == -1)
		{
			printf("accept");
			close_socket(fd);
			exit(-1);
		}
		/* TODO - get message from client */
		char buf[1024];
		int bytes = recv_socket(cfd, buf, 1024);

		if (bytes == -1)
		{
			printf("no bytes!");
			exit(-1);
		}
		buf[bytes] = '\0';
		/* TODO - parse message with parse_command and populate lib */
		char *name = malloc(1024);
		char *func = malloc(1024);
		char *params = malloc(1024);

		int args = parse_command(buf, name, func, params);

		if (args == 1)
		{
			lib.libname = name;
			free(func);
			free(params);
			lib.funcname = NULL;
			lib.filename = NULL;
		}
		else if (args == 2)
		{
			lib.libname = name;
			lib.funcname = func;
			free(params);
			lib.filename = NULL;
		}
		else
		{
			lib.libname = name;
			lib.funcname = func;
			lib.filename = params;
		}

		/* TODO - handle request from client */

		ret = lib_run(&lib);

		int err = send_socket(cfd, lib.outputfile, strlen(OUTPUTFILE_TEMPLATE));
		if (err == -1)
		{
			printf("send");
			return -1;
		}
		close_socket(cfd);
		if (args == 1)
		{
			free(name);
		}
		else if (args == 2)
		{
			free(name);
			free(func);
		}
		else
		{
			free(name);
			free(func);
			free(params);
		}
	}
}

int main(void)
{
	pthread_t threads[8];

	unlink(SOCKET_NAME);
	/* TODO - Implement server connection */
	fd = create_socket();
	if (fd == -1)
	{
		printf("no socket!");
		exit(-1);
	}

	int conn = bind_socket(fd);
	if (conn == -1)
	{
		printf("no connection!");
		close_socket(fd);
		exit(-1);
	}

	if (listen(fd, BACKLOG) == -1)
	{
		printf("listen");
		close_socket(fd);
		exit(-1);
	}

	for (int i = 0; i < 8; i++)
	{
		pthread_create(&threads[i], NULL, thread_funct, NULL);
	}

	for (int i = 0; i < 8; i++)
	{
		pthread_join(threads[i], NULL);
	}

	close_socket(fd);
	return 0;
}

