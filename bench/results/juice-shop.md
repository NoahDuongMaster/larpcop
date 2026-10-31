| Line | Vulnerability | agentkit | Semgrep OSS |
|---|---|---|---|
| `frontend/src/app/app.routing.ts:79` | adminSectionChallenge | – | – |
| `frontend/src/app/app.routing.ts:186` | scoreBoardChallenge | – | – |
| `frontend/src/app/app.routing.ts:239` | web3SandboxChallenge | – | – |
| `frontend/src/app/app.routing.ts:261` | tokenSaleChallenge | – | – |
| `frontend/src/app/app.routing.ts:300` | tokenSaleChallenge | – | – |
| `frontend/src/app/search-result/search-result.component.ts:113` | restfulXssChallenge | `no-bypass-security-trust` | – |
| `frontend/src/app/search-result/search-result.component.ts:146` | localXssChallenge, xssBonusChallenge | `no-bypass-security-trust` | – |
| `lib/insecurity.ts:124` | redirectCryptoCurrencyChallenge | – | – |
| `lib/insecurity.ts:125` | redirectCryptoCurrencyChallenge | – | – |
| `lib/insecurity.ts:126` | redirectCryptoCurrencyChallenge | – | – |
| `lib/insecurity.ts:136` | redirectChallenge | – | – |
| `models/user.ts:73` | weakPasswordChallenge | – | – |
| `routes/chat.ts:179` | chatbotPromptInjectionChallenge, chatbotGreedyInjectionChallenge | – | – |
| `routes/chat.ts:184` | chatbotPromptInjectionChallenge | – | – |
| `routes/login.ts:34` | loginAdminChallenge, loginBenderChallenge, loginJimChallenge | `no-sql-interpolation`, `taint-sql`, `validate-request-input` | `express-sequelize-injection` |
| `routes/search.ts:23` | unionSqlInjectionChallenge, dbSchemaChallenge | `no-sql-interpolation`, `taint-sql`, `validate-request-input` | `express-sequelize-injection` |
| `routes/updateProductReviews.ts:16` | forgedReviewChallenge | `validate-request-input` | – |
| `routes/updateProductReviews.ts:18` | noSqlReviewsChallenge, forgedReviewChallenge | `validate-request-input` | – |
| `routes/updateProductReviews.ts:20` | noSqlReviewsChallenge | `validate-request-input` | – |
| `server.ts:290` | directoryListingChallenge | `no-directory-listing` | `express-check-directory-listing` |
| `server.ts:291` | directoryListingChallenge | `no-directory-listing` | `express-check-directory-listing` |
| `server.ts:302` | accessLogDisclosureChallenge | `no-directory-listing` | `express-check-directory-listing` |
| `server.ts:304` | accessLogDisclosureChallenge | `no-directory-listing` | `express-check-directory-listing` |
| `server.ts:374` | resetPasswordMortyChallenge | – | – |
| `server.ts:398` | changeProductChallenge | – | – |
| `server.ts:539` | registerAdminChallenge | – | – |
| `server.ts:759` | exposedMetricsChallenge | – | – |

- agentkit: 11/27 lines; 405 security findings: validate-request-input 236, secrets 69, no-directory-listing 34, no-bypass-security-trust 15, no-sql-interpolation 13, taint-sql 13, tf-open-ingress 10, no-mongo-where 7, no-eval 4, no-weak-hash 2, no-inner-html 1, taint-redirect 1
- Semgrep OSS: 6/27 lines; 68 security findings: github-actions-mutable-action-tag 7, express-sequelize-injection 6, run-shell-injection 5, aws-subnet-has-public-ip-address 5, aws-elb-access-logs-not-enabled 5, insecure-load-balancer-tls-version 5, express-check-directory-listing 5, express-res-sendfile 4, detected-jwt-token 3, npm-missing-minimum-release-age 2, detect-replaceall-sanitization 2, aws-cloudwatch-log-group-unencrypted 2, detect-non-literal-regexp 2, hardcoded-hmac-key 2, eval-detected 2, gha-curl-pipe-shell 1, detected-generic-secret 1, prototype-pollution-loop 1, path-join-resolve-traversal 1, hardcoded-jwt-secret 1, remote-property-injection 1, express-open-redirect 1, code-string-concat 1, unknown-value-with-script-tag 1, unsafe-formatstring 1, template-explicit-unescape 1

Secrets vs gitleaks: 69 identical findings; 0 only in gitleaks, 0 only in agentkit.
