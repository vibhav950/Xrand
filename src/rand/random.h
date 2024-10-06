/** @file random.h
 *  @brief Random variate generation.
 *
 *  Contains functions for random variate generation for various
 *  probability distributions; Seeded by a fast and compact PRNG.
 *
 *  @author Vibhav Tiwari [vibhav950 on GitHub]
 *
 * LICENSE
 * =======
 *
 * Copyright (C) 2024-25  Xrand
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdio.h>

void uniform(FILE *fp, double a, double b, int iter);
void normal(FILE *fp, double mu, double sigma, int iter);
void triangular(FILE *fp, double a, double b, double c, int iter);
void poisson(FILE *fp, double lambda, int iter);
void binomial(FILE *fp, int n, double p, int iter);
void randstr(FILE *fp, char lc, char uc, char nc, char sc, int len, int iter);
