// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/*
 * jailmaster.c - jailmaster entry file.
 *
 * Copyright (C) 2005-2009 SGDN
 * Authors: 	Olivier Grumelard <clipos@ssi.gouv.fr>
 * 		Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include "jail.h"

int main(void)
{
	if (start_jail()) {
		fprintf(stderr, "Error starting jail\n");
		return 1;
	}
	return 0;
}
