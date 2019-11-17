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

int main(int argc, char **argv)
{
	getdns_list      *to_validate        = NULL;
	getdns_list      *support_records    = NULL;
	getdns_list      *trust_anchors      = NULL;
	FILE             *fh_to_validate     = NULL;
	FILE             *fh_support_records = NULL;
	FILE             *fh_trust_anchors   = NULL;
	getdns_return_t   r = GETDNS_RETURN_GOOD;
	struct tm tm;

	(void)memset(&tm, 0, sizeof(tm));
	if (argc < 3)
		fprintf(stderr, "usage: %s <to_validate> <support_records>"
		                " [ <trust_anchors> ] [ <yyyy-mm-dd> ]\n"
				, argv[0]);

	else if (!(fh_to_validate = fopen(argv[1], "r"))) {
		fprintf(stderr, "Error opening \"%s\"", argv[1]);
		r = GETDNS_RETURN_IO_ERROR;

	} else if ((r = getdns_fp2rr_list(fh_to_validate
	                                 ,  &to_validate, NULL, 3600)))
		fprintf(stderr, "Error reading \"%s\"", argv[1]);

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

	} else if ((r = getdns_validate_dnssec2(
	    to_validate, support_records, trust_anchors,
	    argc > 4 ? mktime(&tm) : time(NULL), 0))) {
		switch (r) {
		case GETDNS_DNSSEC_SECURE:
		case GETDNS_DNSSEC_INSECURE:
		case GETDNS_DNSSEC_INDETERMINATE:
		case GETDNS_DNSSEC_BOGUS:
			printf("%d %s\n", r,
			    getdns_get_errorstr_by_id(r));
			r = GETDNS_RETURN_GOOD;
			break;
		default:
			fprintf(stderr, "Error validaing");
			break;
		};
	}
	if (fh_to_validate)
		(void) fclose(fh_to_validate);

	if (fh_support_records)
		(void) fclose(fh_support_records);

	if (fh_trust_anchors)
		(void) fclose(fh_trust_anchors);

	if (r) {
		fprintf(stderr, ": %s\n", r == GETDNS_RETURN_IO_ERROR ?
		    strerror(errno) : getdns_get_errorstr_by_id(r));
		exit(EXIT_FAILURE);
	}
	return 0;
}
