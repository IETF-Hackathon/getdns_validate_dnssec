/*
 * getdns_validate_dnssec.c - Validate DNSSEC
 *
 * Copyright (c) 2019, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _XOPEN_SOURCE
#include <getdns/getdns_extra.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

/* root_first is needed to route around a bug in the current version of the
   getdns API that requires records in the root to be first.
   It takes in a getdns_list of resource records, and returns it with the shortest
   ones first. All failures are returned early. */
getdns_return_t root_first(getdns_list *in, getdns_list **out)
{
	getdns_return_t r;
	size_t in_len, i, j, j_len, k;
	getdns_dict *rr;
	getdns_bindata *name;
	uint32_t rr_type = 0;

	if ((r = getdns_list_get_length(in, &in_len)))
		return r;

	for (i = 0; i < in_len; i++) {
		if ((r = getdns_list_get_dict(in, i, &rr))
		||  (r = getdns_dict_get_bindata(rr, "name", &name))
		||  (r = getdns_dict_get_int(rr, "type", &rr_type)))
			return r;

		if (name->size == 1 && name->data[0] == 0
		&&  rr_type != GETDNS_RRTYPE_RRSIG)
			break;
	}
	if (i == in_len) {
		*out = in;
		return GETDNS_RETURN_GOOD;
	}
	j = j_len = i;
	k = 0;
		
	if (!(*out = getdns_list_create()))
		return GETDNS_RETURN_MEMORY_ERROR;

	if ((r = getdns_list_set_dict(*out, k++, rr)))
		; /* pass */

	else while (++j < in_len) {
		if ((r = getdns_list_get_dict(in, j, &rr))
		||  (r = getdns_list_set_dict(*out, k++, rr)))
			break;
	}
	if (!r) for (j = 0; j < j_len; j++) {
		if ((r = getdns_list_get_dict(in, j, &rr))
		||  (r = getdns_list_set_dict(*out, k++, rr)))
			break;
	}
	if (r)
		getdns_list_destroy(*out);
	return r;
}

getdns_return_t print_dnssec_status(int status)
{
	switch (status) {
	case GETDNS_DNSSEC_SECURE:
	case GETDNS_DNSSEC_INSECURE:
	case GETDNS_DNSSEC_INDETERMINATE:
	case GETDNS_DNSSEC_BOGUS:
		printf("%i %s\n", status, getdns_get_errorstr_by_id(status));
		return GETDNS_RETURN_GOOD;
	default:
		fprintf(stderr, "Error validating");
		return status;
	};
}

int main(int argc, char **argv)
{
	getdns_list      *to_validate        = NULL;
	getdns_list      *to_validate_fixed  = NULL;
	getdns_list      *support_records    = NULL;
	getdns_list      *trust_anchors      = NULL;
	FILE             *fh_to_validate     = NULL;
	FILE             *fh_support_records = NULL;
	FILE             *fh_trust_anchors   = NULL;
	getdns_return_t   r = GETDNS_RETURN_GOOD;
	struct tm tm;
	char              qtype_str[1024]    = "GETDNS_RRTYPE_";
	getdns_bindata   *qname              = NULL;
	uint32_t          qtype              = GETDNS_RRTYPE_A;
	getdns_dict      *nx_reply           = NULL;
	getdns_list      *nx_list            = NULL;

	(void)memset(&tm, 0, sizeof(tm));
	if (argc < 3)
		fprintf(stderr, "usage: %s <to_validate> <support_records>"
		                " [ <trust_anchors> ] [ <yyyy-mm-dd> ]"
				" [ <dname> ] [ <qtype> ]\n"
				, argv[0]);

	else if (!(fh_to_validate = fopen(argv[1], "r"))) {
		fprintf(stderr, "Error opening \"%s\"", argv[1]);
		r = GETDNS_RETURN_IO_ERROR;

	} else if ((r = getdns_fp2rr_list(fh_to_validate
	                                 ,  &to_validate, NULL, 3600)))
		fprintf(stderr, "Error reading \"%s\"", argv[1]);

	else if ((r = root_first(to_validate, &to_validate_fixed)))
		fprintf(stderr, "Error reordering \"%s\"", argv[1]);

	else if (!(fh_support_records = fopen(argv[2], "r"))) {
		fprintf(stderr, "Error opening \"%s\"", argv[2]);
		r = GETDNS_RETURN_IO_ERROR;

	} else if ((r = getdns_fp2rr_list(fh_support_records
	                                 ,  &support_records, NULL, 3600)))
		fprintf(stderr, "Error reading \"%s\"", argv[2]);

	else if (argc > 3 && !(fh_trust_anchors = fopen(argv[3], "r"))) {
		fprintf(stderr, "Error opening \"%s\"", argv[3]);
		r = GETDNS_RETURN_IO_ERROR;

	} else if (fh_trust_anchors && (r = getdns_fp2rr_list(
	    fh_trust_anchors, &trust_anchors, NULL, 3600)))
		fprintf(stderr, "Error reading \"%s\"", argv[3]);

	else if (!trust_anchors &&
	    !(trust_anchors = getdns_root_trust_anchor(NULL))) {
		fprintf(stderr, "Missing trust anchors");
		r = GETDNS_RETURN_GENERIC_ERROR;

	} else if (argc > 4 && !strptime(argv[4], "%Y-%m-%d", &tm)) {
		fprintf(stderr, "Could not parse date string");
		r = GETDNS_RETURN_IO_ERROR;

	} else if (argc > 5 && (r = getdns_str2bindata(argv[5], &qname)))
		fprintf(stderr, "Could not parse qname");

	else if (argc > 6 &&
	    (r = getdns_str2int(strcat(qtype_str, argv[6]), &qtype)))
		fprintf(stderr, "Could not parse qtype");

	else if (!qname && (r = getdns_validate_dnssec2(
	    to_validate_fixed, support_records, trust_anchors,
	    argc > 4 ? mktime(&tm) : time(NULL), 0)))
		r = print_dnssec_status(r);

	else if (!(nx_reply = getdns_dict_create())) {
		fprintf(stderr, "Could not create nx_reply dict");
		r = GETDNS_RETURN_MEMORY_ERROR;

	} else if ((r = getdns_dict_set_bindata(
	    nx_reply, "/question/qname", qname)))
		fprintf(stderr, "Could not set qname");

	else if ((r = getdns_dict_set_int(
	    nx_reply, "/question/qtype", qtype)))
		fprintf(stderr, "Could not set qtype");

	else if ((r = getdns_dict_set_int(
	    nx_reply, "/question/qclass", GETDNS_RRCLASS_IN)))
		fprintf(stderr, "Could not set qclass");

	else if ((r = getdns_dict_set_list(
	    nx_reply, "/answer", to_validate_fixed)))
		fprintf(stderr, "Could not set answer section");

	else if (!(nx_list = getdns_list_create())) {
		fprintf(stderr, "Could not create nx_list list");
		r = GETDNS_RETURN_MEMORY_ERROR;

	} else if ((r = getdns_list_set_dict(nx_list, 0, nx_reply)))
		fprintf(stderr, "Could not append nx_reply to nx_list");

	else if ((r = getdns_validate_dnssec2(
	    nx_list, support_records, trust_anchors,
	    argc > 4 ? mktime(&tm) : time(NULL), 0)))
		r = print_dnssec_status(r);

	if (to_validate)	getdns_list_destroy(to_validate);
	if (to_validate_fixed && to_validate_fixed != to_validate)
		getdns_list_destroy(to_validate_fixed);
	if (support_records)	getdns_list_destroy(support_records);
	if (trust_anchors)	getdns_list_destroy(trust_anchors);
	if (fh_to_validate)	(void) fclose(fh_to_validate);
	if (fh_support_records)	(void) fclose(fh_support_records);
	if (fh_trust_anchors)	(void) fclose(fh_trust_anchors);
	if (qname)		{ free(qname->data); free(qname); }
	if (nx_reply)		getdns_dict_destroy(nx_reply);
	if (nx_list)		getdns_list_destroy(nx_list);

	if (r) {
		fprintf(stderr, ": %s\n", r == GETDNS_RETURN_IO_ERROR ?
		    strerror(errno) : getdns_get_errorstr_by_id(r));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
