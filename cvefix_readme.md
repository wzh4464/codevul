为了让大模型能够最好地理解这张数据库架构图（ER Diagram），最有效的方式是将其转化为 **SQL DDL（数据定义语言）** 或者 **结构化的 Schema 描述**。

以下是根据图片内容整理的文本，您可以直接将其复制并提供给任何大模型（如 ChatGPT, Claude, Gemini 等），它们都能完美解析并根据此结构回答问题或编写 SQL 代码。

---

### 系统提示词 / Context (可以直接复制)

这里有一个关于软件漏洞（CVE）、代码提交（Commits）和代码库（Repository）的数据库架构。请基于以下 Schema 定义进行分析：

#### 1. 核心漏洞表 (cve)

* **Table Name:** `cve`
* **Primary Key:** `cve_id`
* **Columns:**
* `published_date` (发布日期)
* `last_modified_date` (最后修改日期)
* `description` (描述)
* `nodes`
* `severity` (严重程度)
* `obtain_all_privilege`, `obtain_user_privilege`, `obtain_other_privilege`
* `user_interaction_required`
* `cvss2_vector_string`, `cvss2_access_vector`, `cvss2_access_complexity`, `cvss2_authentication`
* `cvss2_confidentiality_impact`, `cvss2_integrity_impact`, `cvss2_availability_impact`
* `cvss2_base_score`
* `cvss3_vector_string`, `cvss3_attack_vector`, `cvss3_attack_complexity`
* `cvss3_privileges_required`, `cvss3_user_interaction`, `cvss3_scope`
* `cvss3_confidentiality_impact`, `cvss3_integrity_impact`, `cvss3_availability_impact`
* `cvss3_base_score`, `cvss3_base_severity`
* `exploitability_score`, `impact_score`
* `ac_insuf_info`
* `reference_json`, `problemtype_json`



#### 2. 漏洞分类关联表 (cwe_classification)

* **Table Name:** `cwe_classification`
* **Primary Keys / Foreign Keys:**
* `cve_id` (FK ref `cve.cve_id`)
* `cwe_id` (FK ref `cwe.cwe_id`)



#### 3. 弱点枚举表 (cwe)

* **Table Name:** `cwe`
* **Primary Key:** `cwe_id`
* **Columns:**
* `cwe_name`
* `description`
* `extended_description`
* `url`
* `is_category`



#### 4. 修复关联表 (fixes)

这是一个连接 CVE 和具体修复代码提交的中间表。

* **Table Name:** `fixes`
* **Primary Keys / Foreign Keys:**
* `cve_id` (FK ref `cve.cve_id`)
* `hash` (FK ref `commits.hash`)
* `repo_url` (FK ref `repository.repo_url`)



#### 5. 代码库表 (repository)

* **Table Name:** `repository`
* **Primary Key:** `repo_url`
* **Columns:**
* `repo_name`
* `description`
* `date_created`, `date_last_push`
* `homepage`
* `repo_language`
* `owner`
* `forks_count`, `stars_count`



#### 6. 提交记录表 (commits)

* **Table Name:** `commits`
* **Primary Keys:**
* `hash`
* `repo_url` (FK ref `repository.repo_url`)


* **Columns:**
* `author`, `author_date`, `author_timezone`
* `committer`, `committer_date`, `committer_timezone`
* `msg` (提交信息)
* `merge`
* `parents`
* `num_lines_added`, `num_lines_deleted`
* `dmm_unit_complexity`, `dmm_unit_interfacing`, `dmm_unit_size`



#### 7. 文件变更表 (file_change)

* **Table Name:** `file_change`
* **Primary Key:** `file_change_id`
* **Foreign Key:** `hash` (FK ref `commits.hash`)
* **Columns:**
* `filename`
* `old_path`, `new_path`
* `change_type`
* `diff`, `diff_parsed`
* `num_lines_added`, `num_lines_deleted`
* `code_after`, `code_before`
* `nloc` (代码行数)
* `complexity`
* `token_count`
* `programming_language`



#### 8. 方法变更表 (method_change)

记录文件内部具体函数/方法的变更详情。

* **Table Name:** `method_change`
* **Primary Key:** `method_change_id`
* **Foreign Key:** `file_change_id` (FK ref `file_change.file_change_id`)
* **Columns:**
* `name`
* `signature`
* `parameters`
* `start_line`, `end_line`
* `code`
* `nloc`
* `complexity`
* `token_count`
* `top_nesting_level`
* `before_change`



---

### 表之间的关系总结 (Relationships)

1. **CVE to CWE:** 多对多关系。通过 `cwe_classification` 中间表连接 `cve` 和 `cwe`。一个漏洞可以属于多个弱点分类。
2. **CVE to Commits:** 多对多关系。通过 `fixes` 中间表连接。一个 CVE 可以由多个 Commit 修复，一个 Commit 也可以修复多个 CVE。
3. **Repository to Commits:** 一对多关系。一个 `repository` 包含多个 `commits`。
4. **Commits to File Changes:** 一对多关系。一个 Commit (`hash`) 可以包含多个 `file_change` 记录。
5. **File Changes to Method Changes:** 一对多关系。一个文件的变更 (`file_change_id`) 可以包含多个具体方法的变更 (`method_change`)。

---

### 给大模型使用建议

您可以将上述所有内容（包括 Context 和关系总结）直接粘贴到 Prompt 中。
例如：

> "基于上述提供的数据库 Schema，请帮我编写一个 SQL 查询，找出修复了 '严重(Severity)' 等级最高的 CVE 的所有代码提交记录，并列出这些提交所涉及的编程语言。"

您是否需要我为您生成几个针对此 Schema 的 SQL 查询示例？