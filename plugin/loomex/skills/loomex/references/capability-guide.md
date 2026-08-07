---
schemaVersion: loomex.capability-guide/v1
catalogId: loomex-post-auth-capability-guide
catalogVersion: "1"
entryCount: 8
entryFormat: "one Entry section per skill directory"
---

# راهنمای قابلیت‌های Loomex

این catalog مرجع راهنمای پس از آماده‌شدن Loomex، احراز هویت و آماده‌بودن سازمان
و Runner است. هر `Entry` دقیقاً به یک directory واقعی در
`plugin/loomex/skills` مربوط است. شناسه‌ی فنی هر skill در فیلد `id` قابل کپی
است و متن‌های توضیحی برای نمایش به کاربر جدید نوشته شده‌اند.

## راهنمای زبان و مخاطب

- `audience`: کاربر جدید یا کاربری که آماده‌سازی نخست Loomex را با موفقیت کامل
  کرده است.
- `language`: متن توضیحی، عنوان‌ها و قدم بعدی را با زبان گفت‌وگوی جاری کاربر
  ارائه کن؛ لازم نیست متن را به یک زبان ثابت برگردانی.
- `technicalNames`: مقدارهای `id`، نام skillها، نام ابزارهای Loomex، کدها و
  قطعه‌کدهای داخل backtick را دقیقاً بدون ترجمه یا تغییر نگه دار تا کاربر بتواند
  آن‌ها را کپی کند.
- `examples`: جمله‌ی نمونه را هم‌زبان با کاربر ارائه کن، اما نام‌های فنی داخل
  آن را تغییر نده.
- `nextStep`: پس از معرفی هر قابلیت، همین قدم عملی بعدی را روشن و کوتاه بیان
  کن؛ اگر عملیات نیازمند تأیید یا انتخاب کاربر است، همان نقطه را صریح اعلام کن.

## Entry: loomex

- `id`: `loomex`
- `title`: راهنمای اصلی Loomex
- `task`: برای درخواست‌های عمومی Loomex مسیر مناسب را انتخاب می‌کند و بر آماده‌سازی، احراز هویت، سازمان، workflow، اجرای پایدار، درخواست انسانی، approval و وضعیت Runner نظارت دارد.
- `example`: «می‌خواهم با Loomex یک workflow اجرا کنم؛ از آماده‌بودن حساب و سازمانم شروع کن و نتیجه را تا پایان دنبال کن.»
- `nextStep`: درخواست کلی را با همین skill مطرح کن؛ برای کار متمرکز، یکی از skillهای تخصصی مانند `setup`، `login`، `organization-switch`، `create-workflow` یا `workflow` را انتخاب کن.
- `audience`: کاربر جدیدی که هنوز نمی‌داند درخواستش به کدام قابلیت Loomex مربوط است.
- `language`: توضیح مسیر و وضعیت را هم‌زبان گفت‌وگو کن و `loomex` و نام ابزارهای Loomex را تغییر نده.

## Entry: setup

- `id`: `setup`
- `title`: آماده‌سازی و تعمیر Runner
- `task`: نصب، به‌روزرسانی، تعمیر، rollback یا کنترل چرخه‌ی عمر Runner را برای اولین استفاده یا یک درخواست صریح مدیریت می‌کند و نتیجه‌های آماده، pending، خطا و rollback را از هم جدا نگه می‌دارد.
- `example`: «Loomex را برای اولین بار آماده کن و بگو برای ادامه‌ی ورود چه چیزی لازم است.»
- `nextStep`: ابتدا `loomex_setup_status` را بخوان؛ اگر `recommendedNextAction` برابر `setup.plan` بود، طرح `loomex_setup_plan` را نشان بده و فقط پیش از `loomex_setup_apply` تأیید بگیر. پس از آماده‌شدن، به احراز هویت و سازمان ادامه بده.
- `audience`: کاربری که Runner هنوز آماده نیست، نیاز به repair دارد یا صریحاً چرخه‌ی عمر آن را مدیریت می‌کند.
- `language`: توضیح plan، اثر آن و نتیجه‌ی هر وضعیت را هم‌زبان ارائه کن؛ `setup.plan` و نام ابزارها را بدون تغییر بنویس.

## Entry: login

- `id`: `login`
- `title`: ورود، ثبت‌نام و بازیابی حساب
- `task`: ورود به حساب Loomex، ادامه‌ی ثبت‌نام، بازیابی گذرواژه و ادامه پس از تکمیل احراز هویت را از مسیر امن احراز هویت مدیریت می‌کند و بعد از موفقیت، سازمان‌ها را بررسی می‌کند.
- `example`: «وارد Loomex شو؛ اگر حساب ندارم، مسیر ثبت‌نام را در فرم امن ادامه بده.»
- `nextStep`: `loomex_setup_status` و سپس `loomex_auth_status` را بررسی کن؛ در صورت نیاز فرم امن را با `loomex_auth_login` باز کن. پس از موفقیت `loomex_org_list` را بخوان و در صورت نبودن یا تعدد سازمان، به `organization-create` یا `organization-switch` برو.
- `audience`: کاربری که وارد نشده، می‌خواهد حساب بسازد یا دسترسی حسابش را بازیابی کند.
- `language`: فقط وضعیت‌های غیرحساس و قدم‌های قابل‌مشاهده را به زبان جاری توضیح بده؛ نام‌های `login` و ابزارهای احراز هویت را ترجمه نکن.

## Entry: logout

- `id`: `logout`
- `title`: خروج از Loomex در این دستگاه
- `task`: خروج از حساب فعال را با تأیید صریح انجام می‌دهد، زمینه‌ی سازمان و اجرای محلی را پاک می‌کند و در صورت نیاز Runner محلی را متوقف می‌کند؛ حساب و داده‌های دوردست را حذف نمی‌کند.
- `example`: «می‌خواهم از Loomex در این دستگاه خارج شوم؛ چه چیزهایی پاک می‌شود؟»
- `nextStep`: اثر خروج را توضیح بده، تأیید صریح بگیر و سپس `loomex_auth_logout` را با `confirm: true` فراخوانی کن؛ نتیجه‌ی ساختاریافته را بعد از بازگشت گزارش کن.
- `audience`: کاربری که صریحاً می‌خواهد از حساب فعال Loomex در همین دستگاه خارج شود.
- `language`: اثر محلی و مرز اثر خروج را هم‌زبان توضیح بده و `logout`، `loomex_auth_logout` و `confirm: true` را عیناً نگه دار.

## Entry: organization-create

- `id`: `organization-create`
- `title`: ساخت سازمان
- `task`: وقتی حساب احراز‌شده سازمانی ندارد یا کاربر ساخت سازمان می‌خواهد، نام و در صورت ارائه slug را به `loomex_org_create` می‌دهد؛ سازمان ساخته و انتخاب می‌شود و Runner سازمانی bootstrap می‌شود.
- `example`: «یک سازمان به نام تیم محتوا بساز و بعد از آماده‌شدن Runner همان را فعال نگه دار.»
- `nextStep`: مطمئن شو setup و auth آماده‌اند، نام سازمان را بگیر و `loomex_org_create` را با همان نام فراخوانی کن. اگر نتیجه `runner_pending` یا `pending_reconciliation` بود، همان setup action را retry کن و ساخت تکراری انجام نده.
- `audience`: کاربر احراز‌شده‌ای که فهرست سازمانش خالی است یا سازمان جدیدی می‌خواهد.
- `language`: نام سازمان را با زبان کاربر بگیر و وضعیت‌های `runner_ready`، `runner_pending` و `pending_reconciliation` را دقیقاً بدون ترجمه نگه دار.

## Entry: organization-switch

- `id`: `organization-switch`
- `title`: انتخاب سازمان فعال
- `task`: سازمان‌های در دسترس را با نام و ID نشان می‌دهد و با انتخاب دقیق کاربر، سازمان فعال را از طریق `loomex_org_select` عوض می‌کند؛ تغییر انتخاب، execution scope را پاک و bootstrap سازمانی را دوباره انجام می‌دهد.
- `example`: «سازمان‌های Loomex من را فهرست کن و سازمان تیم محتوا را فعال کن.»
- `nextStep`: `loomex_org_list` را بخوان، هنگام ابهام از کاربر انتخاب بگیر و سپس `loomex_org_select` را فقط با `organizationId` دقیق انتخاب‌شده فراخوانی کن.
- `audience`: کاربری که چند سازمان دارد یا صریحاً می‌خواهد سازمان فعال را عوض کند.
- `language`: نام‌ها و توضیح اثر تغییر scope را هم‌زبان ارائه کن، اما `organization-switch`، `loomex_org_list`، `loomex_org_select` و `organizationId` را عیناً نگه دار.

## Entry: create-workflow

- `id`: `create-workflow`
- `title`: ساخت و ذخیره‌ی workflow با AI
- `task`: یک توضیح واقعی و طبیعی از هدف کاربر را به workflow سازمانی قابل‌ذخیره تبدیل می‌کند؛ مسیر ساخت از workflow builder پنهان، مرور agent و در پایان `loomex_workflow_create_finalize` استفاده می‌کند.
- `example`: `loomex:create workflow` — «یک workflow بساز که درخواست انتشار مقاله را بگیرد، از من تأیید بگیرد و نتیجه را اعلام کند.»
- `nextStep`: ابتدا توضیح کامل workflow را از کاربر بگیر، سپس setup، auth و organization scope را آماده کن. بعد `loomex_workflow_list` را با `systemKey: "workflow_builder"`، سپس `loomex_workflow_show`، `loomex_workflow_run` و انتظارهای bounded با `loomex_run_wait` را انجام بده و پس از تکمیل، `loomex_workflow_create_finalize` را یک‌بار فراخوانی کن.
- `audience`: کاربری که می‌خواهد workflow جدیدی را با زبان طبیعی بسازد و ذخیره کند.
- `language`: نیاز و سؤال‌های کاربر را هم‌زبان مطرح کن؛ درخواست اصلی workflow را بازنویسی یا ترجمه نکن و `create-workflow`، `systemKey: "workflow_builder"` و نام ابزارها را تغییر نده.

## Entry: workflow

- `id`: `workflow`
- `title`: فهرست، بررسی و اجرای workflow
- `task`: workflowهای execution model از نوع `plugin` را فهرست می‌کند، جزئیات و ورودی‌ها را بررسی می‌کند و اجرای انتخاب‌شده را با execution ID معتبر تا وضعیت نهایی دنبال می‌کند.
- `example`: `loomex:workflow` — «workflowهایم را فهرست کن؛ جزئیات workflow انتشار مقاله را نشان بده و بعد از تأیید ورودی‌ها آن را اجرا کن.»
- `nextStep`: با `loomex_setup_status` و scope سازمان شروع کن، برای فهرست از `loomex_workflow_list`، برای جزئیات از `loomex_workflow_show` و برای شروع از `loomex_workflow_run` استفاده کن؛ سپس با `loomex_run_wait` ادامه بده تا وضعیت `succeeded`، `failed` یا `cancelled` برگردد.
- `audience`: کاربری که workflow موجود را می‌خواهد پیدا کند، بررسی کند، مقایسه کند یا اجرا کند.
- `language`: نام workflow، ID، version، مسیر workspace و نام ابزارهای Loomex را برای کپی‌کردن بدون تغییر نگه دار و توضیحات و وضعیت اجرا را با زبان گفت‌وگوی جاری ارائه کن.
