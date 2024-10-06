# How to contribute

Contributions from the open-source community are essential in keeping this project up-to-date. There are a few general guidelines you will need to follow if you wish to contribute to Xrand, either by fixing a bug or adding a new feature.

## Reporting an issue

To report a security vulnerability, ask a question, or request a new feature, please open an [issue on GitHub](https://github.com/vibhav950/Xrand/issues/). For more information, see [Creating an issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-an-issue).

Before you report a new issue:

* Look through the [open issues](https://github.com/vibhav950/Xrand/issues) first and make sure a similar one doesn't already exist.
* Please do not issue spam reports or personal support requests (try to use [Stack Overflow](https://stackoverflow.com/) to resolve such queries).

### Reporting a bug

* Try to give a detailed description of your issue, including steps to reproduce the bug, and provide screenshots wherever possible.
* You must provide the crash logs from when the bug was recorded. If you had logs disabled, try to reproduce the problem after re-enabling them.

## Creating a pull request

To submit a patch or implement a new feature, please open a [pull request on GitHub](https://github.com/vibhav950/Xrand/pulls). For more information, check [Creating a pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request).

**Note:** If you wish to add a new feature, open an issue before starting work to get comments from the community. Someone may already be working on the same thing, or there might be good reasons for why the feature doesn't exist.

To make it easier to review and accept your pull requests, please follow the following guidelines:

1. Every file should contain a file header comment (along with the license text) in the following format

   ```c
   /**
    * filename
    *
    * Description of the file
    *
    * yourname
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
   ```

2. Write your code with security in mind - read [this guide](https://github.com/veorq/cryptocoding) to learn about the basic cryptography coding practices. Avoid implementing basic cryptographic features on your own, and use the functionality already available within the library, or from the [OpenSSL API](https://www.openssl.org/docs/index.html).
3. Keep the code portable and maintainable by enforcing adherence to the C standard. On `gcc` or `clang`, you should compile with the `-Wpedantic` and `-Wall` options.
4. Write well-formatted code conforming to the [Linux kernel coding style](https://www.kernel.org/doc/html/v4.10/process/coding-style.html), and provide comments wherever necessary to make it easier for developers to review your code. To further improve code transparency and readability, you should include a description for each function through comments

   ```c
   /**
    * A complete description of the function
    *
    * If the return values have special meanings, you need to
    * explicitly mention them here
    */
   int foo(void)
   {
       ..code..
       /* inline comments for more detail */
       ..code..
   }
   ```

5. Cite the sources - explicitly mention the sources of code snippets, algorithms, or ideas employed in your implementation. This includes references to research papers, articles, or any external material that contributed to the development of the code. For this, you should provide hyperlinks to the source files or other public documents you might have referred to.
6. Try to consolidate related features and components cohesively within a single C file along with its corresponding header file, and avoid changing existing files in the library that are unrelated to your feature.
7. Merge conflicts will not be accepted, you will have to remove them (usually by [rebasing](https://git-scm.com/book/en/v2/Git-Branching-Rebasing)) before it is acceptable.
