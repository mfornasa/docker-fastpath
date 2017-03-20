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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <errno.h>
#include <git2.h>
#include <assert.h>
#include <curl/curl.h>
#include "base64.h"
#include "cJSON.h"
#include "fastpath.h"

int verbose = 0;
int quiet = 0;

int main(int argc, char *argv[]) {
    int i, positional = 0;
    char *revspec = NULL, *image_name = NULL, *username = NULL, *password = NULL;
    char str[BUFSIZE];

    oid_list *candidate_commits;

    for (int i=1; i<argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else {
            if (positional == 0) {
                revspec = argv[i];
            } else if (positional == 1) {
                image_name = argv[i];
            }
            positional++;
        }
    }
    if (revspec == NULL || positional != 2) {
        error("%s", USAGE);
        exit(-1);
    }

    debug("libcurl version: %s\n", LIBCURL_VERSION);
    assert(LIBCURL_VERSION_MAJOR >= 7);
    assert(LIBCURL_VERSION_MAJOR > 7 || LIBCURL_VERSION_MINOR >= 40);

    username = getenv(ENV_VAR_USERNAME);
    password = getenv(ENV_VAR_PASSWORD);

    candidate_commits = fetch_candidate_commits(revspec);

    /*
    debug("Candidate list:\n");
    for (int j=0; j<candidate_commits->size; j++) {
        git_oid_tostr(str, BUFSIZE, oid_list_get(candidate_commits, j));
        debug("  %s\n", str);
    }
    */

// check what happens if I have the local image

    fetch_suitable_images(candidate_commits, image_name, username, password);
    oid_list_free(candidate_commits);
}


int match_regexp(char *regex_str, char *str) {
    regex_t regex;
    char msgbuf[BUFSIZE];
    int reti;

    if (regcomp(&regex, regex_str, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
        error("Could not compile regex: %s\n", str);
        exit(-1);
    }
    reti = regexec(&regex, str, 0, NULL, 0);
    if (!reti) {
        return 1;
    } else if (reti == REG_NOMATCH) {
        return 0;
    } else {
        regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        error("Regex match failed: %s\n", msgbuf);
        exit(-1);
    }
}

int image_status;

static size_t write_function(void *data, size_t size, size_t nmemb, void *userdata) {
    char buffer[nmemb * size +1];

    memcpy(buffer, data, nmemb*size);
    buffer[nmemb*size] = 0;
    //fwrite(data, size, nmemb, stderr);

    if (match_regexp(IMAGE_REGEXP_TAG_CONTINUATION, buffer)) {
        return nmemb*size;
    } else if (match_regexp(IMAGE_REGEXP_TAG_EXISTS, buffer)) {
        image_status = IMAGE_TAG_EXISTS;
        return 0; // Causes a connection abort
    } else if  (match_regexp(IMAGE_REGEXP_TAG_UNKNOWN, buffer)) {
        image_status = IMAGE_TAG_UNKNOWN;
        return 0; // Causes a connection abort
    } else if (match_regexp(IMAGE_REGEXP_REPO_UNKNOWN, buffer)) {
        error("Docker repository unknown: %s\n", buffer);
        exit(-1);
    } else if (match_regexp(IMAGE_REGEXP_BAD_RESPONSE, buffer)) {
        error("%s\n", buffer);
        exit(-1);
    } else {
        error("Error (unknown message): %s\n", buffer);
        exit(-1);
    }
}

int fetch_image(char *image_name, char *tag, char *user, char *pass) {
    FILE *fp;
    CURL *curl = curl_easy_init();
    char str[BUFSIZE], secret[URLSIZE] = "", encoded_secret[URLSIZE], x_registry_auth[URLSIZE], registry_url[URLSIZE], filename[BUFSIZE], *homedir;
    char *buf;
    char url[URLSIZE];

    char *username = user;
    char *password = pass;

    if (!curl) {
        error("Curl init error\n");
        exit(-1);
    }
    CURLcode res;

    // Determine the registry URL
    strcpy(str, image_name);
    char* first_slash =  strchr(str, '/');
    if (first_slash == NULL) {
        // Examples: "debian"
        sprintf(registry_url, "https://%s", DOCKER_HUB_URL_FR);
    } else {
        *first_slash = 0;
        if (strchr(str, '.') == NULL || strchr(str, ':')) {
            // Examples: "gliderlabs/docker-alpine"
            sprintf(registry_url, "https://%s", DOCKER_HUB_URL_FR);
        } else {
            // Examples: "example.com/private"
            sprintf(registry_url, "%s", str);
        }
    }
    debug("Registry URL: %s\n", registry_url);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    if (username && password) {
        debug("Registry credentials defined in environment variables (Username: %s)\n", username);
        sprintf(secret, REGISTRY_CREDENTIALS, username, password, "https://index.docker.io/v1/");
    } else {
        homedir = getenv("HOME");
        if (homedir) {
            debug("Trying to fetch credentials from Docker client configuration\n");
            sprintf(filename, "%s/%s", homedir, CONFIG_FILE_PATH);
            fp = fopen(filename, "r");
            if (fp == NULL) {
                debug("Cannot open Docker client configuration file: %s\n", strerror(errno));
            } else {
                size_t len;
                ssize_t bytes_read = getdelim(&buf, &len, '\0', fp);
                if (bytes_read != -1) {
                    cJSON *root = cJSON_Parse(buf);
                    if (!root) goto end;
                    cJSON *auths = cJSON_GetObjectItem(root, "auths");
                    if (!auths) goto end;
                    cJSON *registry = cJSON_GetObjectItem(auths, registry_url);
                    if (!registry) goto end;
                    char *auth = cJSON_GetObjectItem(registry, "auth")->valuestring;
                    if (!auth) goto end;
                    debug("Found suitable credentials in the configuration file\n");
                    Base64decode(buf, auth);
                    char *delimiter = strchr(buf, ':');
                    username = (char *)malloc(delimiter - buf);
                    password = (char *)malloc(strlen(delimiter + 1));
                    strncpy(username, buf, delimiter - buf);
                    strcpy(password, delimiter+1);
                    sprintf(secret, REGISTRY_CREDENTIALS, username, password, registry_url);
                    free(username);
                    free(password);
end:
                    cJSON_Delete(root);

                } else {
                    error("Error in reading config file: %s\n", strerror(errno));
                    exit(-1);
                }
            }
        }
    }

    if (strlen(secret)>0) {
        Base64encode(encoded_secret, secret, strlen(secret));
        sprintf(x_registry_auth, "X-Registry-Auth: %s", encoded_secret);
        headers = curl_slist_append(headers, x_registry_auth);
    } else {
        debug("No credentials\n");
    }

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, "/var/run/docker.sock");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_function);

    // input sanitation?
    sprintf(url, "http://v1.18/images/create?fromImage=%s&tag=%s", image_name, tag);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    debug("Trying to fetch %s:%s\n", image_name, tag);
    debug("Url: %s\n", url);
    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (res == CURLE_OK) {
        // It should not happen, as I am interrupting the processing
        long response_code = 0L;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        switch(response_code) {
            case 200:
                debug("Tag exists (200)\n");
                // This should not happen
                return IMAGE_TAG_EXISTS;
                break;
            default:
                error("Error fetching image. Response code = %ld\n", response_code);
                exit(-1);
        }
    } else if (res == CURLE_WRITE_ERROR) {
        switch(image_status) {
            case IMAGE_TAG_EXISTS:
                debug("Tag exists\n");
                break;
            case IMAGE_TAG_UNKNOWN:
                debug("Tag does not exist\n");
                break;
            case IMAGE_REPO_UNKNOWN:
                error("Docker repo does not exist");
                exit(-1);
            default:
                error("Wrong return code\n");
                exit(-1);
        }
        return image_status;
    } else {
        info("Error fetching image: %s\n", curl_easy_strerror(res));
        exit(-1);
    }

    curl_easy_cleanup(curl);
}

void fetch_suitable_images(oid_list *candidate_commits, char *image_name, char *username, char *password) {
    char tag[BUFSIZE];
    for (int i=0; i<candidate_commits->size; i++) {
        const git_oid *oid;
        oid = oid_list_get(candidate_commits, i);
        git_oid_tostr(tag, BUFSIZE, oid);

        if (fetch_image(image_name, tag, username, password) == IMAGE_TAG_EXISTS) {
            info("Tag %s has been found in the registry\n", tag);
            printf("%s", tag);
            return;
        }
    }
    info("No suitable image in the registry\n");
}

#define EXIT(status) \
    oid_list_free(hidden_commits); \
    git_revwalk_free(walk); \
    git_repository_free(repo); \
    git_libgit2_shutdown(); \
    exit(status)

oid_list *fetch_candidate_commits(char *revspec) {
    git_revwalk *walk;
    git_object *revspec_obj = NULL;
    git_repository *repo = NULL;
    git_commit *revspec_commit;
    git_otype revspec_type;
    git_oid *revspec_commit_oid;
    oid_list *hidden_commits;
    oid_list *candidate_commits;
    char str[BUFSIZE];
    int i=0;

    // Init libgit2
    git_libgit2_init();
    check_lg2(git_repository_open(&repo, "."));
    check_lg2(git_revwalk_new(&walk, repo));

    // Init internal data structures
    hidden_commits = oid_list_init(MAX_STEPS+1);
    candidate_commits = oid_list_init(MAX_STEPS+1);

    // Sanity check on the provided revspec
    debug("Input revspec: %s\n", revspec);
    check_lg2(git_revparse_single(&revspec_obj, repo, revspec));
    revspec_type = git_object_type(revspec_obj);
    if (revspec_type != GIT_OBJ_COMMIT && revspec_type != GIT_OBJ_TAG) {
        error("Wrong object type %d\n", revspec_type);
        exit(-1);
    }

    // Get the commit object associated with the revspec
    check_lg2(git_commit_lookup(&revspec_commit, repo, git_object_id(revspec_obj)));
    git_oid_tostr(str, BUFSIZE, git_commit_id(revspec_commit));
    info("Commit SHA associated to the input revspec: %s\n", str);

    // Adding the revspec commit to the candidates (repeated build or fast-forward merge)
    oid_list_add(candidate_commits, git_commit_id(revspec_commit));

    // Execute revision walks starting from the revspec commit.
    // At each walk, I prune the commit tree from non-useful branches
    while(i<MAX_STEPS) {
        i++;
        git_oid *oid_match;
        int ret = revwalk_step(&oid_match, walk, repo, revspec_commit, candidate_commits, hidden_commits);
        git_oid_tostr(str, 9, oid_match);
        switch(ret) {
            case REVWALK_NO_DIFF:
                debug("    Found a commit which is identical to the input revspec: %s. Adding to the candidate list\n", str);
                oid_list_add(candidate_commits, oid_match);
                break;
            case REVWALK_DIFF:
                debug("    Found a commit which is different from the input revspec: %s. Adding to the prune list\n", str);
                oid_list_add(hidden_commits, oid_match);
                break;
            case REVWALK_DONE:
                debug("    Commit tree is now empty\n");
                info("Candidate list:\n");
                for (int j=0; j<candidate_commits->size; j++) {
                    git_oid_tostr(str, BUFSIZE, oid_list_get(candidate_commits, j));
                    info("  %s\n", str);
                }
                return(candidate_commits);
            default:
                error("Error: Invalid revwalk_step return value (this should not happen)\n");
                EXIT(-1);
        }
    }
    error("Error: MAX_STEPS (this should not happen)\n");
    EXIT(-1);
}

int revwalk_step(git_oid **oid_match, git_revwalk *walk, git_repository *repo, git_commit *revspec_commit, oid_list *candidate_commits, oid_list *hidden_commits) {
    git_oid oid;
    git_oid *oid_match_out;
    git_tree *base_tree;
    git_diff *diff;
    git_tree *commit_tree;
    git_diff_stats *stats;
    git_commit *commit;
    char str[BUFSIZE];

    debug("Starting revwalk step\n");

    git_revwalk_reset(walk);
    git_revwalk_sorting(walk, GIT_SORT_TOPOLOGICAL);
    check_lg2(git_revwalk_push(walk, git_commit_id(revspec_commit)));

    // revwalk has been reset, so I need to hide previously pruned branches
    for (int j=0; j<hidden_commits->size; j++) {
        const git_oid *t_oid;
        t_oid = oid_list_get(hidden_commits, j);
        git_oid_tostr(str, 9, t_oid);
        debug("    Pruning  %s\n", str);
        check_lg2(git_revwalk_hide(walk, t_oid));
    }

    while (!git_revwalk_next(&oid, walk)) {
        // Skip already considered commits
        int found = 0;
        for (int j=0; j<candidate_commits->size; j++) {
            if (memcmp(oid_list_get(candidate_commits, j), &oid, sizeof(git_oid)) == 0) {
                found = 1;
                break;
            }
        }
        git_oid_tostr(str, 9, &oid);
        if (found) {
            debug("    Skipping %s\n", str);
            continue;
        } else {
            debug("    Diffing  %s. ", str);
        }


        // Compare base tree with current tree
        git_commit_lookup(&commit, repo, &oid);
        check_lg2(git_commit_tree(&base_tree, revspec_commit));
        check_lg2(git_commit_tree(&commit_tree, commit));
        check_lg2(git_diff_tree_to_tree(&diff, repo, base_tree, commit_tree, NULL));
        check_lg2(git_diff_get_stats(&stats, diff));
        int changed = git_diff_stats_files_changed(stats);
        oid_match_out = calloc(sizeof(git_oid), 1);
        memcpy(oid_match_out, &oid, sizeof(git_oid));
        *oid_match = oid_match_out;

        git_commit_free(commit);
        git_tree_free(base_tree);
        git_tree_free(commit_tree);
        git_diff_free(diff);
        git_oid_tostr(str, 9, &oid);

        if (changed) {
            debug("%s is different from the input revspec\n", str);
            return REVWALK_DIFF;
        } else {
            debug("%s is identical to the input revspec\n", str);
            return REVWALK_NO_DIFF;
        }
    }
    *oid_match = NULL;
    debug("    No more commits\n");
    return REVWALK_DONE;
}
oid_list *oid_list_init(unsigned int capacity) {
    oid_list *list;
    list = (oid_list *)calloc(1, sizeof(oid_list));
    list->capacity = capacity;
    list->size = 0;
    list->data = calloc(capacity, sizeof(git_oid *));
    return list;
}

int oid_list_add(oid_list *list, const git_oid *value) {
    if (list->size == list->capacity) {
        return -1;
    }
    list->data[list->size] = (struct git_oid *)calloc(1, sizeof(git_oid));
    memcpy(list->data[list->size], value, sizeof(git_oid));
    list->size++;
    return 0;
}

const git_oid *oid_list_get(oid_list *list, unsigned int index) {
    if (index > list->size-1) {
        return NULL;
    } else {
        return list->data[index];
    }
}

void oid_list_free(oid_list *list) {
    int i;
    for (i=0; i<list->size; i++) {
        free(list->data[i]);
    }
    free(list->data);
    free(list);
}

void _check_lg2(int error, int line) {
    if (error < 0) {
        const git_error *e = giterr_last();
        error("Error on line %d: %d/%d: %s\n", line, error, e->klass, e->message);
        exit(1);
    }
}
