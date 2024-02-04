/**
 * rdrand.h
 *
 * Support for RDRAND and RDSEED instructions on x86 processors.
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

int check_is_intel();
int check_is_amd();

int check_rdrand();
int check_rdseed();

int rdrand_check_support();
int rdseed_check_support();

int rdrand16_step(unsigned short int *therand);
int rdseed16_step(unsigned short int *therand);

int rdrand32_step(unsigned int *therand);
int rdseed32_step(unsigned int *therand);

int rdrand64_step(unsigned long long int *therand);
int rdseed64_step(unsigned long long int *therand);