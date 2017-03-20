/*
 * Copyright (C) 2017 Martino Fornasa <mf@fornasa.it>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <git2.h>

#define DEBUG 1
#define BUFSIZE 255
#define URLSIZE 10000
#define MAX_STEPS 50


// Git
#define REVWALK_NO_DIFF 0
#define REVWALK_DIFF    1
#define REVWALK_DONE    2
#define IMAGE_TAG_EXISTS 0
#define IMAGE_TAG_UNKNOWN 1
#define IMAGE_REPO_UNKNOWN 2

typedef struct {
    unsigned int capacity;
    unsigned int size;
    struct git_oid **data;
} oid_list;


// Local configuration
#define CONFIG_FILE_PATH "/.docker/config.json"
#define ENV_VAR_USERNAME "DOCKER_USERNAME"
#define ENV_VAR_PASSWORD "DOCKER_PASSWORD"


// Registry API and message parsing
/* Note: for private repos I can not distinguish between "tag unknown"
         and "image unknown"
*/
#define IMAGE_REGEXP_TAG_CONTINUATION "Pulling repository"
#define IMAGE_REGEXP_TAG_EXISTS "Pulling from"
#define IMAGE_REGEXP_TAG_UNKNOWN "(Tag|image|manifest for)[^\"]*not found"
#define IMAGE_REGEXP_REPO_UNKNOWN "repository[^\"]*not found"
#define IMAGE_REGEXP_BAD_RESPONSE "Bad response from Docker engine"

#define REGISTRY_CREDENTIALS "\
{\
   \"username\": \"%s\",\
   \"password\": \"%s\",\
   \"serveraddress\": \"%s\"\
}"

#define DOCKER_HUB_URL_FR "index.docker.io/v1/"


// Functions
oid_list *oid_list_init(unsigned int capacity);
int oid_list_add(oid_list *list, const git_oid *value);
const git_oid *oid_list_get(oid_list *list, unsigned int index);
void oid_list_free(oid_list *list);

oid_list *fetch_candidate_commits(char *revspec);
void fetch_suitable_images(oid_list *candidate_commits, char *image_name, char *username, char *password);
int revwalk_step(git_oid **oid_match, git_revwalk *walk, git_repository *repo, git_commit *revspec_commit, oid_list *candidate_commits, oid_list *hidden_commits);
int fetch_image(char *image_name, char *tag, char *username, char *password);


// Error handling + Logging
void _check_lg2(int error, int line);
#define error(...) \
      do { fprintf(stderr, __VA_ARGS__); } while (0)
#define info(...) \
      do { if (!quiet || verbose) fprintf(stderr, __VA_ARGS__); } while (0)
#define debug(...) \
      do { if (verbose) fprintf(stderr, __VA_ARGS__); } while (0)
#define check_lg2(error) _check_lg2(error, __LINE__)


// Usage
#define USAGE "\
USAGE\n       fastpath [<options>] <revspec> <image-name>\n\n\
DESCRIPTION\n\
       <revspec> can be a reference (\"HEAD\") or a SHA commit id.\n\
       <image-name> is the name of the Docker image (without the tag).\n\n\
\n\
       If you use `docker login` before running this command, Docker registry\n\
       credentials are taken from Docker client local configuration.\n\
\n\
       Credentials can also be specified using DOCKER_USERNAME and\n\
       DOCKER_PASSWORD environment variables.\n\
\n\
OPTIONS\n\
       -v, --verbose             Be verbose\n\
       -q, --quiet               Be quiet\n\
"
