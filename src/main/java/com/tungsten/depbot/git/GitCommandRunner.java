package com.tungsten.depbot.git;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Shells out to the {@code git} executable on {@code PATH}.
 *
 * <p>No Java git library is used: every operation here is a single, well-understood command, and
 * shelling out avoids taking on a new dependency for what amounts to a handful of CLI calls.
 *
 * <p>Every method here is a thin, literal wrapper over one git invocation. Deciding what those
 * invocations mean together (is the tree clean enough to proceed, should this change be committed
 * or rolled back) is deliberately not this class's job -- see
 * {@code RemediationCheckoutManager}, {@code RemediationDiffPolicy} and
 * {@code RemediationChangeCommitter}.
 */
public class GitCommandRunner {

    /** Runs {@code git fetch <remote>} in the given repository and returns its combined output. */
    public String fetch(Path repoDirectory, String remote) {
        return run(repoDirectory, "fetch", remote);
    }

    /**
     * Refreshes every remote branch and tag: {@code git fetch --prune --tags <remote>
     * +refs/heads/*:refs/remotes/<remote>/*}.
     *
     * <p>The explicit refspec is the point. A bare {@code git fetch} honours whatever refspec the
     * remote happens to be configured with, which on a clone made with {@code --single-branch} brings
     * back exactly one branch -- and an assessment asked to find the affected release or hotfix branch
     * would then be searching a set of refs that does not contain it. {@code --prune} is what stops a
     * branch deleted upstream from lingering locally and being chosen as a remediation source.
     */
    public String fetchBranchesAndTags(Path repoDirectory, String remote) {
        return run(repoDirectory, "fetch", "--prune", "--tags", remote,
                "+refs/heads/*:refs/remotes/" + remote + "/*");
    }

    /** Runs {@code git rev-parse <ref>} and returns the resolved commit SHA, stripped of whitespace. */
    public String revParse(Path repoDirectory, String ref) {
        return run(repoDirectory, "rev-parse", ref).strip();
    }

    /**
     * The commit a ref points at: {@code git rev-parse --verify <ref>^{commit}}.
     *
     * <p>{@code --verify} makes git fail rather than echo an unresolvable argument back, and
     * {@code ^\{commit\}} dereferences an annotated tag to the commit it tags -- a branch created from
     * a tag object rather than a commit would be rejected by {@code git branch} anyway.
     *
     * @throws GitCommandException if the ref does not resolve to a commit
     */
    public String revParseCommit(Path repoDirectory, String ref) {
        return run(repoDirectory, "rev-parse", "--verify", ref + "^{commit}").strip();
    }

    /**
     * Every ref in the repository, one full name per line: {@code git for-each-ref
     * --format=%(refname)}.
     *
     * <p>Used to check that a ref an assessment named is a ref that genuinely exists, rather than
     * merely something {@code rev-parse} can turn into a commit -- {@code master~5} and
     * {@code HEAD@\{1\}} both resolve, and neither is a branch anyone chose.
     */
    public String listRefs(Path repoDirectory) {
        return run(repoDirectory, "for-each-ref", "--format=%(refname)");
    }

    /** The current branch name, or the literal {@code "HEAD"} when the checkout is detached. */
    public String currentBranch(Path repoDirectory) {
        return run(repoDirectory, "rev-parse", "--abbrev-ref", "HEAD").strip();
    }

    /** The SHA of the current commit, regardless of whether HEAD is on a branch or detached. */
    public String currentHeadSha(Path repoDirectory) {
        return run(repoDirectory, "rev-parse", "HEAD").strip();
    }

    /**
     * Runs {@code git branch <branchName> <startPointSha>} -- creates the ref only, never checks
     * anything out.
     *
     * <p>The start point is always an exact commit SHA, never a branch or ref name: passing a ref
     * would let the new branch track it and drift with future fetches, when the whole point is that
     * every remediation branch is pinned to one fixed commit.
     */
    public void createBranch(Path repoDirectory, String branchName, String startPointSha) {
        run(repoDirectory, "branch", branchName, startPointSha);
    }

    /** Runs {@code git checkout <branchOrSha>}. */
    public void checkout(Path repoDirectory, String branchOrSha) {
        run(repoDirectory, "checkout", branchOrSha);
    }

    /**
     * Pushes {@code branchName} to {@code remote}, creating or updating the remote branch of the same
     * name: {@code git push <remote> <branchName>:<branchName>}. Never force -- a remediation branch is
     * only ever pushed once per commit sequence by this bot, so an ordinary fast-forward push is both
     * sufficient and the safer default; a rejection (the remote branch moved unexpectedly) fails loudly
     * rather than being forced through.
     *
     * <p>The one and only git-publishing operation this application ever performs -- deliberately kept
     * to this single method, mirroring {@code ClaudeToolPolicy.FORBIDDEN_GIT_PUBLISHING}'s ban on
     * {@code git push} for every Claude role. Called only from the publication layer, never from
     * anything Claude-facing.
     */
    public void push(Path repoDirectory, String remote, String branchName) {
        run(repoDirectory, "push", remote, branchName + ":" + branchName);
    }

    /** The raw {@code git status --porcelain} output: empty when the working tree is clean. */
    public String status(Path repoDirectory) {
        return run(repoDirectory, "status", "--porcelain");
    }

    public boolean isClean(Path repoDirectory) {
        return status(repoDirectory).isBlank();
    }

    /** Unstaged changes: working tree against the index. */
    public String diff(Path repoDirectory) {
        return run(repoDirectory, "diff");
    }

    /** Staged changes: index against HEAD. */
    public String diffCached(Path repoDirectory) {
        return run(repoDirectory, "diff", "--cached");
    }

    /** Stages every change, tracked or not. Only ever called by the orchestrator, never by Claude. */
    public void add(Path repoDirectory) {
        run(repoDirectory, "add", "-A");
    }

    public void commit(Path repoDirectory, String message) {
        run(repoDirectory, "commit", "-m", message);
    }

    /** Resets the index and working tree to the given commit. Does not touch untracked files. */
    public void resetHard(Path repoDirectory, String sha) {
        run(repoDirectory, "reset", "--hard", sha);
    }

    /**
     * Moves the current branch to {@code sha} and resets the index to match it, but leaves the working
     * tree untouched -- whatever the commit(s) being moved past changed becomes an ordinary
     * <em>unstaged</em> difference against {@code sha}, exactly as if it had been hand-edited and never
     * {@code git add}-ed. Used to undo a commit Claude made on its own without losing its content, so
     * the usual diff review and commit decision apply to it exactly as they would to an uncommitted
     * change -- including the check that nothing may already be staged when that review begins.
     */
    public void resetMixed(Path repoDirectory, String sha) {
        run(repoDirectory, "reset", "--mixed", sha);
    }

    /** Removes untracked files and directories -- the complement to {@link #resetHard}. */
    public void cleanUntracked(Path repoDirectory) {
        run(repoDirectory, "clean", "-fd");
    }

    /**
     * Every untracked file, one repo-relative path per line, respecting {@code .gitignore}: {@code git
     * ls-files --others --exclude-standard}. Lists files only -- git never tracks directories, so an
     * empty directory (pre-existing or not) never appears here at all.
     *
     * <p>Taking this snapshot before an attempt runs, then again afterward, is what lets a rollback tell
     * a path the attempt itself created apart from one that was already sitting in the working tree
     * beforehand -- see {@code RemediationChangeCommitter}, which never removes the latter.
     */
    public List<String> listUntrackedFiles(Path repoDirectory) {
        String output = run(repoDirectory, "ls-files", "--others", "--exclude-standard");
        return output.lines().filter(line -> !line.isBlank()).toList();
    }

    /** Points a ref directly at a SHA, bypassing any branch. Used for the original-state anchor. */
    public void updateRef(Path repoDirectory, String refName, String sha) {
        run(repoDirectory, "update-ref", refName, sha);
    }

    public void deleteRef(Path repoDirectory, String refName) {
        run(repoDirectory, "update-ref", "-d", refName);
    }

    /**
     * The full, binary-safe diff from {@code baseSha} to {@code candidateSha}: {@code git diff --binary
     * <baseSha> <candidateSha>}. This is the patch handed to the Jenkins {@code SOURCE_PATCH} File
     * Parameter -- it must be reproducible from two commit SHAs alone, so callers always compute it
     * against a specific candidate commit, never against the working tree.
     */
    public String diffBinary(Path repoDirectory, String baseSha, String candidateSha) {
        return run(repoDirectory, "diff", "--binary", baseSha, candidateSha);
    }

    /** The tree SHA a commit points at: {@code git show -s --format=%T <commitSha>}. */
    public String treeSha(Path repoDirectory, String commitSha) {
        return run(repoDirectory, "show", "-s", "--format=%T", commitSha).strip();
    }

    /**
     * A file's content at a fixed commit: {@code git show <sha>:<relativePath>}, or {@code null} if that
     * path did not exist at that commit (a brand-new file/module is a legitimate "not there yet," not an
     * error) -- used by {@link com.tungsten.depbot.implementation.PlanConformanceGate} to compare a
     * planned change's effective value at baseline against its final, post-implementation value.
     */
    public String showFileAt(Path repoDirectory, String sha, String relativePath) {
        try {
            return run(repoDirectory, "show", sha + ":" + relativePath);
        } catch (GitCommandException e) {
            return null;
        }
    }

    /**
     * The working tree (and any commits since) against a fixed commit: {@code git diff <sha>}. Used only
     * to precompute finalization evidence -- Java's own answer to "what has actually changed here,"
     * handed to Claude as prompt text rather than left for Claude to discover with a tool call.
     */
    public String diffAgainst(Path repoDirectory, String sha) {
        return run(repoDirectory, "diff", sha);
    }

    /** As {@link #diffAgainst}, but the {@code --stat} summary form: {@code git diff --stat <sha>}. */
    public String diffStatAgainst(Path repoDirectory, String sha) {
        return run(repoDirectory, "diff", "--stat", sha);
    }

    /**
     * Marks every untracked path's presence in the index without staging its content: {@code git add
     * --intent-to-add --all}. Metadata-only -- never changes file content, and never itself commits
     * anything. Used so a subsequent {@link #diffWorkingTreeAgainst} renders an untracked file as a full
     * "new file" addition (content included) in the same unified diff as tracked staged/unstaged/deleted
     * changes, rather than silently omitting it the way a plain {@code git diff} would.
     */
    public void markIntentToAddAll(Path repoDirectory) {
        run(repoDirectory, "add", "--intent-to-add", "--all");
    }

    /**
     * The current index and working tree against a fixed commit, binary-safe: {@code git diff --binary
     * <baseSha>}. Combined with a prior {@link #markIntentToAddAll} call, this captures staged tracked
     * changes, unstaged tracked changes, deletions, and newly-created untracked files alike, as one single
     * {@code git apply}-able patch -- used to capture an attempted-but-not-committed (or not-yet-cleaned-up)
     * change before it is discarded.
     */
    public String diffWorkingTreeAgainst(Path repoDirectory, String baseSha) {
        return run(repoDirectory, "diff", "--binary", baseSha);
    }

    /**
     * Deletes a local branch: {@code git branch -D <branchName>} (force, since scratch/candidate
     * branches are deleted regardless of whether they were ever merged anywhere).
     *
     * <p>Callers must first move HEAD off {@code branchName} (checkout/detach elsewhere) -- git refuses
     * to delete the currently checked-out branch, and this method does not attempt to work around that.
     */
    public void deleteBranch(Path repoDirectory, String branchName) {
        run(repoDirectory, "branch", "-D", branchName);
    }

    /**
     * Replays {@code commitSha} onto the current HEAD: {@code git cherry-pick <commitSha>}. Returns the
     * SHA of the new commit this creates. Throws {@link GitCommandException} on conflict -- callers must
     * follow a failure with {@link #abortCherryPick} before doing anything else in the repository.
     */
    public String cherryPick(Path repoDirectory, String commitSha) {
        run(repoDirectory, "cherry-pick", commitSha);
        return currentHeadSha(repoDirectory);
    }

    /** Abandons an in-progress, conflicted cherry-pick: {@code git cherry-pick --abort}. */
    public void abortCherryPick(Path repoDirectory) {
        run(repoDirectory, "cherry-pick", "--abort");
    }

    /**
     * Whether {@code ancestorSha} is an ancestor of (or equal to) {@code descendantSha}: {@code git
     * merge-base --is-ancestor <ancestorSha> <descendantSha>}. {@code true} means moving from {@code
     * ancestorSha} to {@code descendantSha} is a pure fast-forward -- nothing reachable only from {@code
     * ancestorSha} would be lost. Exit code 0 means true, exit code 1 means false; neither is treated as
     * a command failure. Any other exit code (a malformed SHA, an unrelated history) is a genuine
     * failure and throws, exactly like every other method here.
     */
    public boolean isAncestor(Path repoDirectory, String ancestorSha, String descendantSha) {
        List<String> command = new ArrayList<>(List.of("git", "merge-base", "--is-ancestor", ancestorSha, descendantSha));
        String description = String.join(" ", command);

        Process process;
        try {
            process = new ProcessBuilder(command).directory(repoDirectory.toFile())
                    .redirectErrorStream(true).start();
        } catch (IOException e) {
            throw new GitCommandException("Could not run \"" + description + "\" in " + repoDirectory, e);
        }

        String output;
        try (InputStream in = process.getInputStream()) {
            output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new GitCommandException("Could not read the output of \"" + description + "\"", e);
        }

        int exitCode;
        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GitCommandException("Interrupted while waiting for \"" + description + "\"", e);
        }

        if (exitCode == 0) {
            return true;
        }
        if (exitCode == 1) {
            return false;
        }
        throw new GitCommandException(
                "\"" + description + "\" failed (exit " + exitCode + ") in " + repoDirectory + ": " + output.strip());
    }

    /**
     * Whether {@code candidateSha} is exactly one commit ahead of {@code parentSha} -- a direct,
     * single-parent child, with no other commits stacked in between and no second parent (a merge).
     * Enforces "one accepted group, one commit": a candidate that is zero commits ahead (no new commit
     * at all), more than one commit ahead, or a merge commit must never be silently fast-forwarded onto
     * the cumulative branch as if it were a single group's own change.
     */
    public boolean isDirectChild(Path repoDirectory, String candidateSha, String parentSha) {
        if (candidateSha.equals(parentSha)) {
            return false;
        }
        String firstParent;
        try {
            firstParent = revParse(repoDirectory, candidateSha + "^");
        } catch (GitCommandException e) {
            return false;
        }
        if (!firstParent.equals(parentSha)) {
            return false;
        }
        try {
            revParse(repoDirectory, candidateSha + "^2");
            return false;
        } catch (GitCommandException e) {
            return true;
        }
    }

    /** Whether {@code refs/heads/<branchName>} exists in the local repository. */
    public boolean branchExistsLocally(Path repoDirectory, String branchName) {
        return listRefs(repoDirectory).lines().anyMatch(ref -> ref.equals("refs/heads/" + branchName));
    }

    /**
     * Every commit SHA reachable from {@code ref}, newest first: {@code git log --format=%H <ref>}. Used
     * only to confirm a persisted commit sequence ({@code CohortsIndex.Entry.commits()}) is genuinely
     * present, in the recorded order, on the branch a publication is about to push -- never to discover
     * commits some other way.
     */
    public List<String> commitHistory(Path repoDirectory, String ref) {
        String output = run(repoDirectory, "log", "--format=%H", ref);
        return output.lines().filter(line -> !line.isBlank()).toList();
    }

    /**
     * The URL configured for {@code remote}: {@code git remote get-url <remote>}. Read-only -- used only
     * to verify, before any push, that this checkout's remote genuinely points at the GitLab project the
     * REST API config names, never to discover or choose a remote.
     */
    public String remoteUrl(Path repoDirectory, String remote) {
        return run(repoDirectory, "remote", "get-url", remote).strip();
    }

    /**
     * The SHA {@code refs/heads/<branchName>} currently points at on {@code remote}, or {@code null} if
     * no such branch exists there: {@code git ls-remote <remote> refs/heads/<branchName>}. Read-only --
     * never mutates the remote, and is how a retry confirms an already-open Merge Request's branch still
     * matches what was actually published before deciding whether it is safe to proceed without pushing
     * again.
     */
    public String lsRemoteSha(Path repoDirectory, String remote, String branchName) {
        String output = run(repoDirectory, "ls-remote", remote, "refs/heads/" + branchName).strip();
        if (output.isBlank()) {
            return null;
        }
        int tab = output.indexOf('\t');
        return (tab < 0 ? output : output.substring(0, tab)).strip();
    }

    private String run(Path repoDirectory, String... args) {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.addAll(Arrays.asList(args));
        String description = String.join(" ", command);

        Process process;
        try {
            process = new ProcessBuilder(command)
                    .directory(repoDirectory.toFile())
                    .redirectErrorStream(true)
                    .start();
        } catch (IOException e) {
            throw new GitCommandException("Could not run \"" + description + "\" in " + repoDirectory, e);
        }

        String output;
        try (InputStream in = process.getInputStream()) {
            output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new GitCommandException("Could not read the output of \"" + description + "\"", e);
        }

        int exitCode;
        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GitCommandException("Interrupted while waiting for \"" + description + "\"", e);
        }

        if (exitCode != 0) {
            throw new GitCommandException(
                    "\"" + description + "\" failed (exit " + exitCode + ") in " + repoDirectory
                            + ": " + output.strip());
        }
        return output;
    }
}
