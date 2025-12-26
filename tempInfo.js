/**
 * * =======================================================================
 * * COMMIT MESSAGE CONVENTION (Conventional Commits enforced by Husky/Commitlint)
 * * This format is required to ensure automatic versioning and changelog generation.
 * * =======================================================================
 * * FORMAT:
 * <type>(<optional scope>): <subject>
 * * [optional body]
 * * [optional footer(s)]
 * * -----------------------------------------------------------------------
 * * 1. HEADER RULES:
 * * - Type:      MUST be one of the allowed types (see below), in lowercase.
 * - Scope:     OPTIONAL. A section of the codebase (e.g., 'auth', 'ui', 'api').
 * - Subject:   REQUIRED. A concise, imperative, present-tense description.
 * - Length:    Limit the first line (header) to 50 characters max.
 * - Punctuation: DO NOT end the subject with a period (.).
 * - Tense:     Use imperative, present tense (e.g., "add", not "added").
 * * -----------------------------------------------------------------------
 * * 2. ALLOWED TYPES (The 'feat' and 'fix' types trigger version bumps):
 * * - feat:      A new feature or capability for the user. (Minor Version)
 * - fix:       A bug fix for the user. (Patch Version)
 * - docs:      Changes exclusively to documentation.
 * - style:     Code formatting changes (whitespace, missing semicolons, etc.).
 * - refactor:  A code change that neither fixes a bug nor adds a feature.
 * - perf:      A code change that improves performance.
 * - test:      Adding or correcting tests.
 * - chore:     Routine tasks, general maintenance, or dependency updates.
 * - build:     Changes that affect the build system or external dependencies.
 * - ci:        Changes to CI/CD configuration files and scripts.
 * - revert:    Reverts a previous commit.
 * * -----------------------------------------------------------------------
 * * 3. BODY & FOOTER RULES:
 * * - Body:       Separate from the header by a BLANK LINE. Use to explain the
 * 'why' and motivation for the change. Wrap lines at 100 chars.
 * - Footer:     Separate from the body by a BLANK LINE. Used for Issue references
 * and BREAKING CHANGES.
 * - Breaking:   A breaking change MUST be indicated by:
 * a) Appending '!' to the type/scope (e.g., `feat!: subject`) OR
 * b) Starting a footer with: `BREAKING CHANGE: <description>`
 * * -----------------------------------------------------------------------
 * * EXAMPLE:
 * * feat(auth): add email validation check
 * * This update integrates a new utility function to validate
 * the email format against RFC 5322 before saving a new user.
 * This prevents invalid data from reaching the database.
 * * Closes #145
 * */

// docker run -d --name mph-redis-bull -p 6380:6379 redis
// docker-compose up -d --build
// docker-compose logs -f
