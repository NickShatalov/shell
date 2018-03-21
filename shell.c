//author: Nick Shatalov
//email: nick.shatalov@mail.ru


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

/*************/
/* constants */
/*************/

enum {
	init_buf_size = 256,
	start_path_len = 64
};

enum {
	eof_end,
	newline_end,
	space_end,
	ampersand_end,
	less_end,
	greater_end,
	greater_end_nsp,
	vertical_bar_end
};

enum {
	ampersand_sym = 1,
	less_sym,
	greater_sym,
	greater_sym_nsp,
	double_gr_sym,
	vertical_bar_sym
};

enum {
	process_exit_err = 1,
	chdir_err,
	ampersand_err,
	redirection_err,
	in_stream_err,
	out_stream_err,
	chdir_usage_err
};

/**************/
/* structures */
/**************/

struct buffer
{
	char* data;
	int size;
	int cur;
};

struct item
{
	char* data;
	char special_sym;
	struct item *next;
};

struct queue {
	struct item *first;
	struct item *last;
};

struct options {
	int err;
	char background;
	char* redirection[2];
	char append;
};

struct cmd_item {
	int pid;
	char **argv;
	struct cmd_item *next;
};

struct cmd_queue {
	struct cmd_item *first;
	struct cmd_item *last;
};

/* copies src string with length len to dest string */
void copy_len_str(const char *src, char *dest, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		dest[i] = src[i];
	}
}

/* classic strcmp function */
int strcmp(const char *str1, const char *str2)
{
	while (*str1 && *str2) {
		if (*str1 > *str2)
			return 1;
		if (*str1 < *str2)
			return -1;
		str1++;
		str2++;
	}

	if (*str1)
		return 1;
	if (*str2)
		return -1;

	return 0;
}

/********************/
/* buffer functions */
/********************/

void init_buffer(struct buffer *buf, int size)
{
	buf->data = malloc(size);
	buf->size = size;
	buf->cur = 0;
}

void free_buffer(struct buffer *buf)
{
	free(buf->data);
	buf->data = NULL;
	buf->size = 0;
	buf->cur = 0;
}

void add_new_sym_to_buffer(struct buffer *buf, char sym)
{
	buf->data[buf->cur] = sym;
	buf->cur++;
}

char get_last_sym_from_buffer(struct buffer buf)
{
	if (buf.cur > 0)
		return buf.data[buf.cur - 1];
	return 0;
}

/* doubles size of buffer buf (with coping data) */
void double_buffer(struct buffer *buf)
{
	char *new_data = malloc(buf->size * 2);
	copy_len_str(buf->data, new_data, buf->size);
	free(buf->data);
	buf->data = new_data;
	buf->size *= 2;
}

/* returns string with data from buffer, resets buffer */
char *flush_buffer(struct buffer *buf)
{
	char *str = malloc(buf->cur + 1);

	buf->data[buf->cur] = 0;
	copy_len_str(buf->data, str, buf->cur + 1);
	buf->cur = 0;

	return str;
}

/*******************/
/* queue functions */
/*******************/

void init_queue(struct queue *q)
{
	q->first = NULL;
	q->last = NULL;
}

void free_list(struct item **first)
{
	struct item *tmp;

	while (*first != NULL) {
		tmp = (*first)->next;
		if ((*first)->data != NULL) {
			free((*first)->data);
		}
		free(*first);
		*first = tmp;
	}
}

void free_queue(struct queue *q)
{
	free_list(&q->first);
	q->last = NULL;
}

/* adds new node to queue */
void add2queue3(struct queue *q, char *data, char special_sym)
{
	struct item *tmp = malloc(sizeof(*tmp));
	tmp->next = NULL;
	tmp->data = data;
	tmp->special_sym = special_sym;

	if (q->last == NULL)
		q->first = tmp;
	else
		q->last->next = tmp;
	q->last = tmp;
}

void add2queue(struct queue *q, char *data)
{
	add2queue3(q, data, 0);
}

void del_item(struct item **itm)
{
	struct item *tmp;

	if (*itm == NULL)
		return;
	
	tmp = (*itm)->next;
	free(*itm);
	*itm = tmp;
}

int cmd_len_in_list(const struct item *first)
{
	int len = 0;
	while ((first != NULL) && (first->special_sym != vertical_bar_sym)) {
		first = first->next;
		len++;
	}

	return len;
}

/* converts list to data structure for execvp */
char **cmd_list_2_argv(const struct item *first)
{
	int length = cmd_len_in_list(first);
	int i;
	char **argv; 
	
	if (first == NULL) {
		return NULL;
	}

	argv = malloc((length + 1) * sizeof(char*));
	argv[length] = NULL;

	i = 0;
	while ((first != NULL) && (first->special_sym != vertical_bar_sym)) {
		argv[i] = first->data;
		first = first->next;
		i++;
	}

	return argv;
}

/***********************/
/* pid queue functions */
/***********************/

void init_cmd_queue(struct cmd_queue *q)
{
	q->first = NULL;
	q->last = NULL;
}

void free_cmd_list(struct cmd_item **first)
{
	struct cmd_item *tmp;

	while (*first != NULL) {
		tmp = (*first)->next;
		free(*first);
		*first = tmp;
	}
}

void free_cmd_queue(struct cmd_queue *q)
{
	free_cmd_list(&q->first);
	q->last = NULL;
}

void add_2_cmd_queue(struct cmd_queue *q, char **argv)
{
	struct cmd_item *tmp = malloc(sizeof(*tmp));
	tmp->next = NULL;
	tmp->pid = 0;
	tmp->argv = argv;

	if (q->last == NULL)
		q->first = tmp;
	else
		q->last->next = tmp;
	q->last = tmp;
}

int cmd_list_len(struct cmd_item *q)
{
	int len = 0;
	while (q) {
		q = q->next;
		len++;
	}
	return len;
}

/*********************/
/* semantic analysys */
/*********************/

void init_options(struct options *opt)
{
	opt->err = 0;
	opt->background = 0;
	opt->redirection[0] = NULL;
	opt->redirection[1] = NULL;
	opt->append = 0;
}

int is_double_gr_sym(struct item *cur)
{
	if (cur->special_sym != greater_sym)
		return 0;
	if (cur->next == NULL)
		return 0;
	if (cur->next->special_sym != greater_sym_nsp)
		return 0;
	return 1;
}

void check_double_gr_sym(struct item **cur)
{
	if (*cur == NULL)
		return;

	if ((*cur)->special_sym == greater_sym_nsp) 
		(*cur)->special_sym = greater_sym;

	if (is_double_gr_sym(*cur)) {
		del_item(cur);
		(*cur)->special_sym = double_gr_sym;
	}
}

int check_ampersand(struct item **cur, struct options *opt)
{
	if (*cur == NULL) {
		return 0;
	}
	if ((*cur)->special_sym == ampersand_sym) {
		if ((*cur)->next == NULL) {
			del_item(cur);
			opt->background = 1;
			return 1;
		}
		else {
			opt->err = ampersand_err;
			return -1;
		}
	}
	return 0;
}

int check_redirection(struct item **cur, struct options *opt)
{
	int fd;
	if (*cur == NULL) {
		return 0;
	}
	switch ((*cur)->special_sym) {
		case less_sym:
			fd = 0;
			break;
		case greater_sym:
			fd = 1;
			opt->append = 0;
			break;
		case double_gr_sym:
			fd = 1;
			opt->append = 1;
			break;
		default:
			return 0;
	}
	del_item(cur);
	if (*cur == NULL) {
		opt->err = redirection_err;
		return -1;
	}
	if ((*cur)->data != NULL) {
		if (opt->redirection[fd] == NULL) {
			opt->redirection[fd] = (*cur)->data;
		}
		else {
			opt->err = redirection_err;	
		}
	}
	else {
		opt->err = redirection_err;
		return -1;
	}
	del_item(cur);
	return 1;
}

int is_vertical_bar(struct item **cur)
{
	if ((*cur)->special_sym == vertical_bar_sym)
		return 1;
	return 0;
}

struct cmd_item *get_argv_list(struct item **arg_list, struct options *opt)
{
	struct cmd_queue pid_q;
	struct item **cur = arg_list;

	init_cmd_queue(&pid_q);

	while (*cur != NULL) {
		switch(check_ampersand(cur, opt)) {
			case -1:
				return NULL;
			case 1:
				continue;
		}

		check_double_gr_sym(cur);
		
		switch(check_redirection(cur, opt)) {
			case -1:
				return NULL;
			case 1:
				continue;
		}
		
		if (is_vertical_bar(cur)) {
			add_2_cmd_queue(&pid_q, cmd_list_2_argv(*arg_list));
			del_item(cur);
			arg_list = cur;
			continue;
		}

		cur = &((*cur)->next);
	}

	add_2_cmd_queue(&pid_q, cmd_list_2_argv(*arg_list));
	return pid_q.first;
}

int argv_len(char **argv)
{
	int i = 0;
	while (argv[i] != NULL) {
		i++;
	}

	return i;
}

/*******************/
/* input functions */
/*******************/

int is_separator_sym(char sym)
{
	return sym == ' ' ||
		   sym == '\n' ||
		   sym == '&' ||
		   sym == '<' ||
		   sym == '>' ||
		   sym == '|';
}

/*
 * gets one argument from input line
 *
 * returns:
 * eof_end == 0 - if last argument ended with EOF
 * newline_end == 1 - \n (new line)
 * space_end == 2 - space
 */

int get_return_value(char sym, char no_spaces)
{
	switch (sym) {
		case ' ':
			return space_end;
		case '\n':
			return newline_end;
		case '&':
			return ampersand_end;
		case '<':
			return less_end;
		case '>':
			if (no_spaces)
				return greater_end_nsp;
			else
				return greater_end;
		case '|':
			return vertical_bar_end;
	}
	return 0;
}

int get_arg(char **arg, struct buffer *buf)
{
	int sym;
	char multiword = 0;
	char new_word = 0;
	char no_spaces = 1;
	*arg = NULL;

	while ((sym = getchar()) != EOF) {
		if (sym == '\"') {
			multiword = !multiword;
			continue;
		}
		if ((sym == ' ') && !new_word) {
			no_spaces = 0;
			continue;
		}
		if (!multiword && is_separator_sym(sym)) {
			if (new_word) {
				*arg = flush_buffer(buf);
				new_word = 0;
			}
		
			return get_return_value(sym, no_spaces);
		}
	
		if (buf->cur >= buf->size)
			double_buffer(buf);

		add_new_sym_to_buffer(buf, sym);
		new_word = 1;
		no_spaces = 0;
	}
	
	return eof_end;
}

/*
 * puts by pointer "first" list of arguments in input line
 * returns:
 * eof_end == 0 - if last argument ended with EOF (end program)
 * newline_end == 1 - \n (new line) (continue program)
 */

int get_arg_list(struct item **first, struct buffer *buf)
{
	int status;
	struct queue q;

	init_queue(&q);

	for (;;) {
		char* arg;
		status = get_arg(&arg, buf);

		if (arg)
			add2queue(&q, arg);
		
		if (status == ampersand_end)
			add2queue3(&q, NULL, ampersand_sym);
		if (status == less_end)
			add2queue3(&q, NULL, less_sym);
		if (status == greater_end)
			add2queue3(&q, NULL, greater_sym);
		if (status == greater_end_nsp)
			add2queue3(&q, NULL, greater_sym_nsp);
		if (status == vertical_bar_end)
			add2queue3(&q, NULL, vertical_bar_sym);

		if (status == eof_end || status == newline_end)
			break;
	}

	*first = q.first;
	return status;
}

/* prints list of args to stdout */
void print_arg_list(const struct item *first)
{
	for (; first; first = first->next)
		printf("[%s]\n", first->data);
}

/***********************/
/* execution functions */
/***********************/

void kill_zombies()
{
	int child_pid;
	int child_status;

	while ((child_pid = wait4(-1, &child_status, WNOHANG, NULL)) > 0) {
		if (WIFEXITED(child_status)) {
			printf("[bg] %d Exited, code: %d\n", 
					child_pid,
					WEXITSTATUS(child_status)
			);
		}
		else {
			printf("[bg] %d Got signal, code: %d\n", 
					child_pid,
					WTERMSIG(child_status)
			);
		}
	}
}

int check_ch_dir(struct cmd_item *cmd_list)
{
	int cmd_num = cmd_list_len(cmd_list);
	char ch_dir_st = 0;
	while (cmd_list) {
		if ((cmd_list->argv) && (strcmp(cmd_list->argv[0], "cd") == 0)) {
			ch_dir_st = 1;
		}
		cmd_list = cmd_list->next;
	}
	if (ch_dir_st && (cmd_num > 1)) {
		fprintf(stderr, "Invalid use of cd in pipe\n");
		return -1;
	}
	return ch_dir_st;
}

/* changes directory to the 1st argument (or HOME dir) */
int ch_dir(char **argv)
{
	char *dir;
	if (argv_len(argv) < 2) {
		dir = getenv("HOME");
		if (dir == NULL) {
			fprintf(stderr, "HOME is undefined\n");
			return chdir_err;
		}
	}
	else {
		dir = argv[1];
	}

	if (chdir(dir) == -1) {
		perror(dir);
		return chdir_err;
	}
	return 0;
}

int open_in_stream(struct options opt)
{
	if (opt.redirection[0] != NULL) {
		int fd = open(opt.redirection[0], O_RDONLY);
		if (fd == -1) {
			perror(opt.redirection[0]);
		}
		return fd;
	}
	return 0;
}

int open_out_stream(struct options opt)
{
	if (opt.redirection[1] != NULL) {
		int open_mode;
		int fd;
		if (opt.append == 1) {
			open_mode = O_APPEND;
		}
		else {
			open_mode = O_TRUNC;
		}
		fd =
			open(opt.redirection[1],
				O_WRONLY | O_CREAT | open_mode,
				0666
			);
		if (fd == -1) {
			perror(opt.redirection[1]);
		}
		return fd;
	}
	return 1;
}

int open_streams(int *fd, struct options opt)
{
	if ((fd[0] = open_in_stream(opt)) == -1)
		return in_stream_err;

	if ((fd[1] = open_out_stream(opt)) == -1)
		return out_stream_err;

	return 0;
}

void redirect_stream(int *fd, int stream)
{
	if ((stream < 0) && (stream > 1))
		return; 

	if (fd[stream] != stream) {
		dup2(fd[stream], stream);
		close(fd[stream]);
	}
}

void close_streams(int *fd)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (fd[i] != i)
			close(fd[i]);
	}
}

int *fork_exec_processes(struct cmd_item *cmd_list, int *redirect_fd)
{
	char is_first = 1, is_last = 0;
	int i = 0;
	int fd[2], prev_fd;
	int *arr_pid = malloc(cmd_list_len(cmd_list) * sizeof(int));

	while (cmd_list) {
		is_last = (cmd_list->next == NULL);
		
		if (!is_last)
			pipe(fd);

		arr_pid[i] = fork();
		if (arr_pid[i] == 0) { /* child */
			if (is_first) {
				redirect_stream(redirect_fd, 0);
			}
			else {
				dup2(prev_fd, 0);
				close(prev_fd);
			}

			if (is_last) {
				redirect_stream(redirect_fd, 1);
			}
			else {
				dup2(fd[1], 1);
				close(fd[1]);
				close(fd[0]);
			}
			execvp(cmd_list->argv[0], cmd_list->argv);
			perror(cmd_list->argv[0]);
			exit(1);
		}
		if (!is_first)
			close(prev_fd);
		if (!is_last)
			close(fd[1]);
		prev_fd = fd[0];
		is_first = 0;
		i++;
		cmd_list = cmd_list->next;
	}

	return arr_pid;
}

char is_free(int *arr_pid, int pid_num)
{
	int i;
	for (i = 0; i < pid_num; i++) {
		if (arr_pid[i] != 0)
			return 0;
	}
	return 1;
}

int rm_pid(int pid, int *arr_pid, int pid_num)
{
	int i;
	for (i = 0; i < pid_num; i++) {
		if (arr_pid[i] == pid) {
			arr_pid[i] = 0;
			return 0;
		}
	}
	return 1;
}

int wait_processes(int *arr_pid, int pid_num)
{
	int i;
	int res = 0;
	for (i = 0; i < pid_num; i++) {
		int wait_st;
		while (!is_free(arr_pid, pid_num)) {
			int pid = wait(&wait_st);
			rm_pid(pid, arr_pid, pid_num);
			if (WIFEXITED(wait_st) && WEXITSTATUS(wait_st) != 0) {
				res = process_exit_err;
			}
		}
	}
	return res;
}

/* executes program */
int exec(struct cmd_item *cmd_list, struct options opt)
{
	int pid_num = cmd_list_len(cmd_list);
	int *arr_pid;
	int redirect_fd[2];
	int stream_st = open_streams(redirect_fd, opt);
	
	if (stream_st != 0)
		return stream_st;

	arr_pid = fork_exec_processes(cmd_list, redirect_fd);
	close_streams(redirect_fd);
	free_cmd_list(&cmd_list);

	if (!opt.background) {
		/*
		int wait_st;
		while (wait(&wait_st) != pid)
			{};
		if (WIFEXITED(wait_st) && WEXITSTATUS(wait_st) != 0) {
			return process_exit_err;
		}
		*/
		return wait_processes(arr_pid, pid_num);
	}
	
	/*printf("[bg] %d\n", pid);*/
	return 0;
}

void print_error(int err)
{
	switch(err) {
		case ampersand_err: {
			fprintf(stderr, "Unexpected & (must be in the end)\n");
			break;
		}
		case redirection_err: {
			fprintf(stderr, "Invalid use of \"<\"/\">\"/\">>\"\n");
			break;
		}
	}
}

int execute(struct item **first)
{
	struct options opt;
	struct cmd_item *cmd_list;
	char **argv; /* delete it */
	int res;
	int ch_dir_st;

	init_options(&opt);
	cmd_list = get_argv_list(first, &opt);

	ch_dir_st = check_ch_dir(cmd_list);
	switch (ch_dir_st) {
		case -1:
			return chdir_usage_err;
		case 1:
			return ch_dir(cmd_list->argv);
	}

	/* remove it */
	if (cmd_list != NULL) {
		argv = cmd_list->argv;
	}
	else {
		return 0;
	}
	/*************/

	if (opt.err) {
		print_error(opt.err);
		return opt.err;
	}

	res = exec(cmd_list, opt);
	
	free(argv);
	return res;
}

char* get_wd()
{
	struct buffer buf;
	init_buffer(&buf, start_path_len);
	while (!getcwd(buf.data, buf.size)) {
		double_buffer(&buf);
	}

	return buf.data;
}

int main()
{
	struct buffer buf;
	init_buffer(&buf, init_buf_size);

	for(;;) {
		struct item *arg_list = NULL;
		int arg_list_st;
		char *user = getenv("USER");
		char *pwd = get_wd();

		kill_zombies();

		printf("[%s %s]$ ", user, pwd);
		fflush(stdout);
		free(pwd);
		arg_list_st = get_arg_list(&arg_list, &buf);

		/* print_arg_list(arg_list); */
		execute(&arg_list);

		free_list(&arg_list);
		if (arg_list_st == eof_end)
			break;
	}

	free_buffer(&buf);

	return 0;
}
