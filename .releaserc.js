module.exports = {
  branches: [
    "main"
  ], // Branch to trigger releases from
  plugins: [
    "@semantic-release/commit-analyzer", // Analyze commit messages
    [
      "@semantic-release/npm", // Publish to NPM
      {
        npmPublish: true,
      },
    ],
    [
      "@semantic-release/git", // Commit and push updated files
      {
        assets: [
          "package.json"
        ],
        message: "chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}",
      },
    ],
  ],
};
