"""替身机器人话术模板（18 语种）——大模型缺席时的确定性文案。

双引擎架构里小模型（Needle 3）只抽取意图，大模型（Reasoner）只写人话。但大模型可
能被关掉、被限流、超时、返回非 200，甚至根本没配 —— 那时主人收到的不能是空字符串，
也不能是一句英文硬编码。本模块因此承担两件职责：

* 给 :mod:`app.reasoner_bridge` 一份**逐语种对齐**的模板目录，任何回退路径都能渲染出
  该语种的自然语言（``render`` 永远返回非空字符串，永远不抛）；
* 给后台与自检一份可校验的契约：``KINDS`` 是话术种类，``PLACEHOLDERS`` 是每种的占位符
  集合，``missing_keys`` / ``extra_keys`` / ``placeholder_drift`` / ``assert_catalog``
  把 18 语种的对齐状态变成断言 —— 与 :mod:`app.i18n` 同一套纪律，只是这里的单位是
  「一句话术」而不是「一个界面词条」。

占位符约定沿用 :data:`app.i18n._PLACEHOLDER_RE`（``{lower_snake}``）：译文里少了占位符
就等于丢信息（比如没写时区的确认文案），所以 ``placeholder_drift`` 是硬门禁而不是提示。
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .i18n import FALLBACK_LOCALE, LOCALES, normalize_locale, placeholders

# 话术种类：日历答复 / 提案确认 / 纪要 / 访客 / A2A 协商 / 过期。
KINDS: Tuple[str, ...] = (
    "availability_answer",
    "availability_none",
    "create_confirm",
    "proposal_pending",
    "reschedule_confirm",
    "cancel_confirm",
    "meeting_summary",
    "guest_received",
    "guest_booked",
    "negotiation_converged",
    "negotiation_failed",
    "proposal_expired",
)

# Needle 3 抽到的工具名 -> 回天话术种类。提案落库后的确认文案走 *  _confirm 三条。
KIND_FOR_TOOL: Dict[str, str] = {
    "calendar.get_availability": "availability_answer",
    "calendar.propose_create": "create_confirm",
    "calendar.propose_reschedule": "reschedule_confirm",
    "calendar.propose_cancel": "cancel_confirm",
    "workspace.summarize_file": "meeting_summary",
}

_TOKEN_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")

# 文字系统门禁：译文里混进别的文字族（例如匈牙利句里蹦出一个汉字）几乎一定是复制粘贴
# 事故，占位符对齐检查是发现不了的。这里按语种列出「允许出现的非拉丁文字族」。
_HAN = re.compile(r"[㐀-䶿一-鿿]")
_KANA = re.compile(r"[぀-ヿ]")
_THAI = re.compile(r"[฀-๿]")
_CYRILLIC = re.compile(r"[Ѐ-ӿ]")
_SCRIPT_FAMILIES: Dict[str, str] = {
    "han": "中日韩汉字",
    "kana": "日文假名",
    "thai": "泰文",
    "cyrillic": "西里尔字母",
}
_SCRIPT_ALLOWED: Dict[str, Tuple[str, ...]] = {
    "zh-Hans": ("han",),
    "zh-Hant": ("han",),
    "ja": ("han", "kana"),
    "th": ("thai",),
    "ru": ("cyrillic",),
    "bg": ("cyrillic",),
    "uk": ("cyrillic",),
}
_SCRIPT_TESTS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("han", _HAN),
    ("kana", _KANA),
    ("thai", _THAI),
    ("cyrillic", _CYRILLIC),
)


def foreign_scripts(locale: str, text: str) -> List[str]:
    """Which other-family scripts show up in *text* for *locale* (empty = clean)."""
    allowed = set(_SCRIPT_ALLOWED.get(resolve_locale(locale), ()))
    found = [name for name, pattern in _SCRIPT_TESTS if name not in allowed and pattern.search(text or "")]
    return found

# 基准语种的话术：其余 17 语种必须与这一份的键集与占位符集合完全一致。
CATALOG: Dict[str, Dict[str, str]] = {}

CATALOG["en"] = {
    "availability_answer": (
        "Thanks {sender} — I'm free for {duration} minutes at: {options}. "
        "Timezone: {timezone}. Which one works for you?"
    ),
    "availability_none": (
        "Sorry {sender}, my calendar has no free slot inside {window}. Could we widen "
        "the window or pick another day?"
    ),
    "create_confirm": (
        "Confirmed: {title} from {start} to {end} ({timezone}). It is in the calendar now."
    ),
    "reschedule_confirm": (
        "Moved: {title} now starts at {to} (it was {from}), timezone {timezone}."
    ),
    "proposal_pending": "Proposal ready: {title} from {start} to {end} ({timezone}). Waiting for the owner to confirm; nothing is in the calendar yet.",
    "cancel_confirm": (
        "Cancelled: {title} on {start} ({timezone}) no longer blocks your day."
    ),
    "meeting_summary": "Summary of {file_name}: {headline} Follow-up actions: {actions}",
    "guest_received": (
        "Thanks {host} — your request is in. Proposed slot: {start} ({timezone}). You will "
        "get a calendar invite once they confirm."
    ),
    "guest_booked": (
        "Booked with {host}: {start} ({timezone}). Your link code is {code}."
    ),
    "negotiation_converged": (
        "{peer} and I agreed on {start} for {duration} minutes. Sending the invite now."
    ),
    "negotiation_failed": (
        "I could not find a slot that works with {peer}: {reason}. Shall I propose another time?"
    ),
    "proposal_expired": (
        "{title} on {start} was not confirmed in time, so nothing was written to the calendar."
    ),
}

CATALOG["zh-Hans"] = {
    "availability_answer": "{sender} 你好，我 {duration} 分钟的空档有：{options}（时区 {timezone}）。哪个时间方便？",
    "availability_none": "{sender} 抱歉，{window} 内我的日历没有空档，能否放宽时段或改约别的日子？",
    "create_confirm": "已确认：{title}，{start} 至 {end}（{timezone}），已写入日历。",
    "reschedule_confirm": "已改期：{title} 从 {from} 挪到 {to}（时区 {timezone}）。",
    "proposal_pending": "已生成待确认提案：{title}，{start} 至 {end}（{timezone}）。主人确认后才会写入日历。",
    "cancel_confirm": "已取消：{start} 的「{title}」（{timezone}）不再占用日程。",
    "meeting_summary": "{file_name} 纪要：{headline} 待办事项：{actions}",
    "guest_received": "{host} 已收到你的预约请求，建议时段：{start}（{timezone}）。对方确认后你会收到日历邀请。",
    "guest_booked": "已与 {host} 约定：{start}（{timezone}）。你的链接码是 {code}。",
    "negotiation_converged": "我与 {peer} 已敲定 {start}，时长 {duration} 分钟，正在发送邀请。",
    "negotiation_failed": "没能和 {peer} 找到共同空档：{reason}。需要我再提个别的时间吗？",
    "proposal_expired": "{start} 的「{title}」未在规定时间内确认，日历未做任何改动。",
}

CATALOG["zh-Hant"] = {
    "availability_answer": "{sender} 你好，我 {duration} 分鐘的空檔有：{options}（時區 {timezone}）。哪個時間方便？",
    "availability_none": "{sender} 抱歉，{window} 內我的行事曆沒有空檔，能否放寬時段或改約別的日子？",
    "create_confirm": "已確認：{title}，{start} 至 {end}（{timezone}），已寫入行事曆。",
    "reschedule_confirm": "已改期：{title} 從 {from} 挪到 {to}（時區 {timezone}）。",
    "proposal_pending": "已產生待確認提案：{title}，{start} 至 {end}（{timezone}）。主人確認後才會寫入行事曆。",
    "cancel_confirm": "已取消：{start} 的「{title}」（{timezone}）不再佔用行程。",
    "meeting_summary": "{file_name} 會議記錄：{headline} 待辦事項：{actions}",
    "guest_received": "{host} 已收到你的預約請求，建議時段：{start}（{timezone}）。對方確認後你會收到行事曆邀請。",
    "guest_booked": "已與 {host} 約定：{start}（{timezone}）。你的連結碼是 {code}。",
    "negotiation_converged": "我與 {peer} 已敲定 {start}，時長 {duration} 分鐘，正在發送邀請。",
    "negotiation_failed": "沒能和 {peer} 找到共同空檔：{reason}。需要我再提別的時間嗎？",
    "proposal_expired": "{start} 的「{title}」未在規定時間內確認，行事曆未做任何變動。",
}

CATALOG["ja"] = {
    "availability_answer": (
        "{sender} 様、{duration} 分間の空き枠は次の通りです：{options}（タイムゾーン {timezone}）。"
        "ご都合の良い時間はどれですか？"
    ),
    "availability_none": (
        "{sender} 様、申し訳ありません。{window} の範囲に空きがありません。"
        "時間帯を広げるか、別の日をご検討いただけますか？"
    ),
    "create_confirm": "確定しました：{title}、{start}〜{end}（{timezone}）。カレンダーに登録済みです。",
    "reschedule_confirm": "変更しました：{title} は {from} から {to} に移動しました（タイムゾーン {timezone}）。",
    "proposal_pending": "提案を作成しました：{title}、{start}〜{end}（{timezone}）。本人が確認するまでカレンダーには書き込みません。",
    "cancel_confirm": "キャンセルしました：{start} の「{title}」（{timezone}）は予定から削除されました。",
    "meeting_summary": "{file_name} の要約：{headline} 今後の対応：{actions}",
    "guest_received": (
        "{host} よりリクエストを受け付けました。提案枠：{start}（{timezone}）。"
        "承認後にカレンダー招待をお送りします。"
    ),
    "guest_booked": "{host} と確定しました：{start}（{timezone}）。リンクコードは {code} です。",
    "negotiation_converged": "{peer} と {start}（{duration} 分）で合意しました。招待をお送りします。",
    "negotiation_failed": "{peer} と都合の合う枠が見つかりませんでした：{reason}。別の時間を提案しましょうか？",
    "proposal_expired": "{start} の「{title}」は確認期限までに承認されなかったため、カレンダーは変更していません。",
}

CATALOG["bg"] = {
    "availability_answer": (
        "Здравей, {sender} — имам свободни {duration} минути в тези часове: {options}. "
        "Часова зона: {timezone}. Кой от тях е удобен?"
    ),
    "availability_none": (
        "Съжалявам, {sender}, в рамките на {window} нямам свободен час. Можем ли да разширим "
        "периода или да изберем друга дата?"
    ),
    "create_confirm": "Потвърдено: {title} от {start} до {end} ({timezone}). Записано е в календара.",
    "reschedule_confirm": "Преместено: {title} вече започва {to} (преди беше {from}), часова зона {timezone}.",
    "proposal_pending": "Предложението е готово: {title} от {start} до {end} ({timezone}). Чака потвърждение от собственика - в календара още няма запис.",
    "cancel_confirm": "Отменено: {title} на {start} ({timezone}) вече не заема деня ви.",
    "meeting_summary": "Резюме на {file_name}: {headline} Последващи стъпки: {actions}",
    "guest_received": (
        "Благодаря, {host} — заявката е получена. Предложен час: {start} ({timezone}). "
        "Ще получите покана след потвърждение."
    ),
    "guest_booked": "Запазено с {host}: {start} ({timezone}). Кодът на връзката ви е {code}.",
    "negotiation_converged": "С {peer} се споразумяхме за {start}, {duration} минути. Изпращам поканата.",
    "negotiation_failed": "Не намерих удобен час с {peer}: {reason}. Да предложа ли друг час?",
    "proposal_expired": (
        "{title} на {start} не беше потвърдено навреме, затова в календара не е записано нищо."
    ),
}

CATALOG["cs"] = {
    "availability_answer": (
        "Děkuji, {sender} — mám volno {duration} minut v těchto časech: {options}. "
        "Časové pásmo: {timezone}. Který vám vyhovuje?"
    ),
    "availability_none": (
        "Omlouvám se, {sender}, v okně {window} nemám volno. Můžeme rozšířit čas "
        "nebo zvolit jiný den?"
    ),
    "create_confirm": "Potvrzeno: {title} od {start} do {end} ({timezone}). Zapsáno v kalendáři.",
    "reschedule_confirm": "Přesunuto: {title} nyní začíná {to} (dříve {from}), časové pásmo {timezone}.",
    "proposal_pending": "Návrh je připraven: {title} od {start} do {end} ({timezone}). Čeká na potvrzení vlastníkem - v kalendáři ještě nic není.",
    "cancel_confirm": "Zrušeno: {title} na {start} ({timezone}) už vám neruší den.",
    "meeting_summary": "Shrnutí {file_name}: {headline} Úkoly: {actions}",
    "guest_received": (
        "Děkuji, {host} — vaše žádost je přijata. Navržený termín: {start} ({timezone}). "
        "Po potvrzení dostanete pozvánku."
    ),
    "guest_booked": "Zamluveno s {host}: {start} ({timezone}). Váš kód odkazu je {code}.",
    "negotiation_converged": "S {peer} jsme se dohodli na {start}, {duration} minut. Posílám pozvánku.",
    "negotiation_failed": "Nenašel jsem termín, který by vyhovoval i {peer}: {reason}. Nabídnout jiný čas?",
    "proposal_expired": "{title} na {start} nebylo včas potvrzeno, do kalendáře jsem nic nezapsal.",
}

CATALOG["de"] = {
    "availability_answer": (
        "Danke {sender} — ich habe {duration} Minuten frei an diesen Zeiten: {options}. "
        "Zeitzone: {timezone}. Was passt Ihnen?"
    ),
    "availability_none": (
        "Leider habe ich im Fenster {window} keinen freien Termin, {sender}. Können wir "
        "das Fenster erweitern oder einen anderen Tag wählen?"
    ),
    "create_confirm": "Bestätigt: {title} von {start} bis {end} ({timezone}). Steht jetzt im Kalender.",
    "reschedule_confirm": "Verschoben: {title} beginnt jetzt {to} (war {from}), Zeitzone {timezone}.",
    "proposal_pending": "Vorschlag erstellt: {title} von {start} bis {end} ({timezone}). Wartet auf die Bestätigung - im Kalender steht noch nichts.",
    "cancel_confirm": "Abgesagt: {title} am {start} ({timezone}) blockiert Ihren Tag nicht mehr.",
    "meeting_summary": "Zusammenfassung von {file_name}: {headline} Nachbereitungen: {actions}",
    "guest_received": (
        "Danke {host} — Ihre Anfrage ist eingegangen. Vorgeschlagener Termin: {start} "
        "({timezone}). Nach der Bestätigung erhalten Sie eine Einladung."
    ),
    "guest_booked": "Gebucht mit {host}: {start} ({timezone}). Ihr Link-Code ist {code}.",
    "negotiation_converged": "{peer} und ich haben {start} für {duration} Minuten vereinbart. Einladung geht raus.",
    "negotiation_failed": "Ich habe mit {peer} keinen passenden Termin gefunden: {reason}. Soll ich eine andere Zeit vorschlagen?",
    "proposal_expired": "{title} am {start} wurde nicht rechtzeitig bestätigt — der Kalender bleibt unverändert.",
}

CATALOG["es"] = {
    "availability_answer": (
        "Gracias {sender}: tengo {duration} minutos libres en estas horas: {options}. "
        "Zona horaria: {timezone}. ¿Cuál te viene bien?"
    ),
    "availability_none": (
        "Lo siento {sender}, no tengo hueco en la ventana {window}. ¿Ampliamos el rango "
        "o elegimos otro día?"
    ),
    "create_confirm": "Confirmado: {title} de {start} a {end} ({timezone}). Ya está en el calendario.",
    "reschedule_confirm": "Cambiado: {title} ahora empieza {to} (antes {from}), zona horaria {timezone}.",
    "proposal_pending": "Propuesta lista: {title} de {start} a {end} ({timezone}). Esperando la confirmación del titular; aún no hay nada en el calendario.",
    "cancel_confirm": "Cancelado: {title} del {start} ({timezone}) ya no ocupa tu agenda.",
    "meeting_summary": "Resumen de {file_name}: {headline} Tareas pendientes: {actions}",
    "guest_received": (
        "Gracias {host}, recibí tu solicitud. Propuesta: {start} ({timezone}). Recibirás "
        "una invitación cuando se confirme."
    ),
    "guest_booked": "Reservado con {host}: {start} ({timezone}). Tu código de enlace es {code}.",
    "negotiation_converged": "{peer} y yo coincidimos en {start}, {duration} minutos. Envío la invitación.",
    "negotiation_failed": "No encontré un hueco común con {peer}: {reason}. ¿Propongo otra hora?",
    "proposal_expired": "{title} del {start} no se confirmó a tiempo, así que no toqué el calendario.",
}

CATALOG["fi"] = {
    "availability_answer": (
        "Kiitos {sender} — minulla on {duration} minuuttia vapaata näihin aikoihin: {options}. "
        "Aikavyöhyke: {timezone}. Mikä sopii?"
    ),
    "availability_none": (
        "Valitettavasti {sender} minulla ei ole vapaita hetkiä ikkunassa {window}. "
        "Voimmeko laajentaa aikaa tai valita toisen päivän?"
    ),
    "create_confirm": "Vahvistettu: {title} {start} → {end} ({timezone}). Kirjattu kalenteriin.",
    "reschedule_confirm": "Siirretty: {title} alkaa nyt {to} (oli {from}), aikavyöhyke {timezone}.",
    "proposal_pending": "Ehdotus luotu: {title} {start} - {end} ({timezone}). Odottaa omistajan vahvistusta - kalenterissa ei vielä ole mitään.",
    "cancel_confirm": "Peruttu: {title} {start} ({timezone}) ei enää varaa päivääsi.",
    "meeting_summary": "Yhteenveto tiedostosta {file_name}: {headline} Seuraavat toimet: {actions}",
    "guest_received": (
        "Kiitos {host} — pyyntösi on vastaanotettu. Ehdotettu aika: {start} ({timezone}). "
        "Saat kutsun vahvistuksen jälkeen."
    ),
    "guest_booked": "Varattu {host}: {start} ({timezone}). Linkkikoodisi on {code}.",
    "negotiation_converged": "{peer} kanssa päästiin yhteiseen aikaan {start}, kesto {duration} minuuttia. Lähetän kutsun.",
    "negotiation_failed": "En löytänyt {peer} kanssa sopivaa aikaa: {reason}. Ehdotanko toista aikaa?",
    "proposal_expired": "Ehdotusta {title} ({start}) ei vahvistettu määräajassa, joten kalenteriin ei kirjoitettu mitään.",
}

CATALOG["fr"] = {
    "availability_answer": (
        "Merci {sender} — je suis disponible {duration} minutes à ces créneaux : {options}. "
        "Fuseau horaire : {timezone}. Lequel vous arrange ?"
    ),
    "availability_none": (
        "Désolé {sender}, aucun créneau libre sur {window}. Peut-on élargir la fenêtre "
        "ou choisir un autre jour ?"
    ),
    "create_confirm": "Confirmé : {title} de {start} à {end} ({timezone}). C'est au calendrier.",
    "reschedule_confirm": "Déplacé : {title} commence désormais {to} (avant {from}), fuseau horaire {timezone}.",
    "proposal_pending": "Proposition créée : {title} de {start} à {end} ({timezone}). En attente de la confirmation du titulaire ; rien n'est encore au calendrier.",
    "cancel_confirm": "Annulé : {title} du {start} ({timezone}) ne bloque plus votre journée.",
    "meeting_summary": "Résumé de {file_name} : {headline} Actions à suivre : {actions}",
    "guest_received": (
        "Merci {host} — votre demande est bien reçue. Créneau proposé : {start} ({timezone}). "
        "Vous recevrez l'invitation après confirmation."
    ),
    "guest_booked": "Réservé avec {host} : {start} ({timezone}). Votre code de lien est {code}.",
    "negotiation_converged": "{peer} et moi avons convenu de {start} pour {duration} minutes. J'envoie l'invitation.",
    "negotiation_failed": "Impossible de trouver un créneau commun avec {peer} : {reason}. Je propose une autre heure ?",
    "proposal_expired": "{title} du {start} n'a pas été confirmé à temps, le calendrier reste inchangé.",
}

CATALOG["hu"] = {
    "availability_answer": (
        "Köszönöm {sender} — {duration} percig vagyok szabad ezeken az időpontokon: {options}. "
        "Időzóna: {timezone}. Melyik felel meg neked?"
    ),
    "availability_none": (
        "Sajnos {sender} a(z) {window} ablakban nincs szabad időpontom. Tágíthatjuk "
        "az időszakot vagy választhatunk másik napot?"
    ),
    "create_confirm": "Megerősítve: {title} {start} és {end} között ({timezone}). Felvettem a naptárba.",
    "reschedule_confirm": "Áthelyezve: {title} most {to}-kor kezdődik (eredetileg {from}), időzóna {timezone}.",
    "proposal_pending": "Javaslat elkészült: {title}, {start} - {end} ({timezone}). A tulajdonos megerősítésére vár - a naptárban még nincs bejegyzés.",
    "cancel_confirm": "Lemondva: {title} {start} ({timezone}) többé nem foglalja a napodat.",
    "meeting_summary": "{file_name} összefoglalója: {headline} Teendők: {actions}",
    "guest_received": (
        "Köszönöm {host} — a kérését megkaptam. Javasolt időpont: {start} ({timezone}). "
        "A jóváhagyás után meghívót küldök."
    ),
    "guest_booked": "Időpont foglalva {host} részére: {start} ({timezone}). A linkkód: {code}.",
    "negotiation_converged": "{peer} és én megegyeztünk: {start}, {duration} perc. Küldöm a meghívót.",
    "negotiation_failed": "Nem találtunk közös időpontot a partneremmel ({peer}): {reason}. Javasoljak másik időpontot?",
    "proposal_expired": "{title} {start} nem lett megerősítve időben, a naptárba nem írtam semmit.",
}

CATALOG["it"] = {
    "availability_answer": (
        "Grazie {sender}: ho {duration} minuti liberi in questi orari: {options}. "
        "Fuso orario: {timezone}. Quale ti va bene?"
    ),
    "availability_none": (
        "Mi dispiace {sender}, nella finestra {window} non ho orari liberi. Possiamo "
        "allargare la finestra o scegliere un altro giorno?"
    ),
    "create_confirm": "Confermato: {title} dalle {start} alle {end} ({timezone}). È in calendario.",
    "reschedule_confirm": "Spostato: {title} ora inizia {to} (prima {from}), fuso orario {timezone}.",
    "proposal_pending": "Proposta creata: {title} da {start} a {end} ({timezone}). In attesa della conferma del titolare; nel calendario non c'è ancora nulla.",
    "cancel_confirm": "Annullato: {title} del {start} ({timezone}) non occupa più la tua agenda.",
    "meeting_summary": "Riepilogo di {file_name}: {headline} Azioni da svolgere: {actions}",
    "guest_received": (
        "Grazie {host}, ho ricevuto la richiesta. Proposta: {start} ({timezone}). "
        "Riceverai l'invito dopo la conferma."
    ),
    "guest_booked": "Prenotato con {host}: {start} ({timezone}). Il tuo codice link è {code}.",
    "negotiation_converged": "Io e {peer} abbiamo concordato {start}, {duration} minuti. Invio l'invito.",
    "negotiation_failed": "Non ho trovato un orario comune con {peer}: {reason}. Propongo un altro momento?",
    "proposal_expired": "{title} del {start} non è stato confermato in tempo, il calendario è rimasto invariato.",
}

CATALOG["nl"] = {
    "availability_answer": (
        "Bedankt {sender} — ik heb {duration} minuten vrij op deze momenten: {options}. "
        "Tijdzone: {timezone}. Wat schikt je?"
    ),
    "availability_none": (
        "Helaas {sender}, binnen {window} heb ik geen vrije plek. Kunnen we het venster "
        "verbreden of een andere dag kiezen?"
    ),
    "create_confirm": "Bevestigd: {title} van {start} tot {end} ({timezone}). Staat in de agenda.",
    "reschedule_confirm": "Verplaatst: {title} begint nu {to} (was {from}), tijdzone {timezone}.",
    "proposal_pending": "Voorstel klaar: {title} van {start} tot {end} ({timezone}). Wacht op bevestiging van de eigenaar - er staat nog niets in de agenda.",
    "cancel_confirm": "Geannuleerd: {title} op {start} ({timezone}) blokkeert je dag niet meer.",
    "meeting_summary": "Samenvatting van {file_name}: {headline} Volgende acties: {actions}",
    "guest_received": (
        "Dank je {host} — je verzoek is binnen. Voorgesteld tijdstip: {start} ({timezone}). "
        "Na bevestiging krijg je een uitnodiging."
    ),
    "guest_booked": "Geboekt bij {host}: {start} ({timezone}). Je linkcode is {code}.",
    "negotiation_converged": "{peer} en ik hebben {start} afgesproken voor {duration} minuten. Ik stuur de uitnodiging.",
    "negotiation_failed": "Ik vond geen passend moment met {peer}: {reason}. Zal ik een andere tijd voorstellen?",
    "proposal_expired": "{title} op {start} is niet op tijd bevestigd, dus de agenda is onveranderd.",
}

CATALOG["pl"] = {
    "availability_answer": (
        "Dzięki {sender} — mam {duration} minut wolnego w tych terminach: {options}. "
        "Strefa czasowa: {timezone}. Który pasuje?"
    ),
    "availability_none": (
        "Niestety {sender}, w oknie {window} nie mam wolnego terminu. Możemy poszerzyć "
        "okno albo wybrać inny dzień?"
    ),
    "create_confirm": "Potwierdzono: {title} od {start} do {end} ({timezone}). Zapisane w kalendarzu.",
    "reschedule_confirm": "Przeniesiono: {title} zaczyna się teraz {to} (było {from}), strefa czasowa {timezone}.",
    "proposal_pending": "Propozycja gotowa: {title} od {start} do {end} ({timezone}). Czeka na potwierdzenie właściciela - w kalendarzu jeszcze nic nie ma.",
    "cancel_confirm": "Anulowano: {title} {start} ({timezone}) nie zajmuje już Twojego dnia.",
    "meeting_summary": "Podsumowanie {file_name}: {headline} Zadania: {actions}",
    "guest_received": (
        "Dziękuję {host} — Twoje zgłoszenie dotarło. Proponowany termin: {start} ({timezone}). "
        "Po potwierdzeniu dostaniesz zaproszenie."
    ),
    "guest_booked": "Zarezerwowano z {host}: {start} ({timezone}). Twój kod linku to {code}.",
    "negotiation_converged": "Z {peer} ustaliliśmy {start} na {duration} minut. Wysyłam zaproszenie.",
    "negotiation_failed": "Nie znalazłem wspólnego terminu z {peer}: {reason}. Proponować inną godzinę?",
    "proposal_expired": "{title} {start} nie zostało potwierdzone na czas, więc w kalendarzu nic nie zapisałem.",
}

CATALOG["ru"] = {
    "availability_answer": (
        "Спасибо, {sender} — у меня есть {duration} минут свободно в это время: {options}. "
        "Часовой пояс: {timezone}. Что удобнее?"
    ),
    "availability_none": (
        "К сожалению, {sender}, в окне {window} свободных слотов нет. "
        "Можно расширить окно или выбрать другой день?"
    ),
    "create_confirm": "Подтверждено: {title} с {start} до {end} ({timezone}). Записано в календарь.",
    "reschedule_confirm": "Перенесено: {title} теперь начинается {to} (было {from}), часовой пояс {timezone}.",
    "proposal_pending": "Предложение готово: {title} с {start} до {end} ({timezone}). Ждёт подтверждения владельцем - в календаре пока ничего нет.",
    "cancel_confirm": "Отменено: {title} на {start} ({timezone}) больше не занимает день.",
    "meeting_summary": "Краткое содержание {file_name}: {headline} Задачи: {actions}",
    "guest_received": (
        "Спасибо, {host} — ваш запрос получен. Предлагаемое время: {start} ({timezone}). "
        "После подтверждения придёт приглашение."
    ),
    "guest_booked": "Забронировано с {host}: {start} ({timezone}). Код вашей ссылки: {code}.",
    "negotiation_converged": "Мы с {peer} договорились на {start}, {duration} минут. Отправляю приглашение.",
    "negotiation_failed": "Не удалось найти удобное время с {peer}: {reason}. Предложить другой слот?",
    "proposal_expired": "{title} на {start} не подтверждено вовремя — в календарь ничего не записано.",
}

CATALOG["th"] = {
    "availability_answer": (
        "ขอบคุณ {sender} — ว่าง {duration} นาทีในช่วงเหล่านี้: {options} (เขตเวลา {timezone}) เวลาใดสะดวก?"
    ),
    "availability_none": (
        "ขออภัย {sender} ในช่วง {window} ยังไม่มีเวลาว่าง ปรับช่วงให้กว้างขึ้นหรือเลือกวันอื่นได้ไหม?"
    ),
    "create_confirm": "ยืนยันแล้ว: {title} เวลา {start} ถึง {end} ({timezone}) บันทึกลงในปฏิทินแล้ว",
    "reschedule_confirm": "เลื่อนแล้ว: {title} เริ่มที่ {to} (เดิม {from}) เขตเวลา {timezone}",
    "proposal_pending": "สร้างคำขอแล้ว: {title} เวลา {start} ถึง {end} ({timezone}) รอเจ้าของยืนยัน ยังไม่มีอะไรในปฏิทิน",
    "cancel_confirm": "ยกเลิกแล้ว: {title} วันที่ {start} ({timezone}) ไม่ยึดตารางของคุณอีกต่อไป",
    "meeting_summary": "สรุปไฟล์ {file_name}: {headline} งานต่อเนื่อง: {actions}",
    "guest_received": "ขอบคุณ {host} รับคำขอแล้ว เสนอเวลา {start} ({timezone}) คุณจะได้รับคำเชิญเมื่ออีกฝ่ายยืนยัน",
    "guest_booked": "จองกับ {host} เรียบร้อย: {start} ({timezone}) รหัสลิงก์ของคุณคือ {code}",
    "negotiation_converged": "ตกลงกับ {peer} ได้ที่เวลา {start} นาน {duration} นาที กำลังส่งคำเชิญ",
    "negotiation_failed": "หาเวลาตรงกับ {peer} ไม่สำเร็จ: {reason} ให้เสนอเวลาอื่นไหม?",
    "proposal_expired": "{title} วันที่ {start} ไม่ได้รับการยืนยันภายในกำหนด จึงไม่ได้แก้ไขปฏิทิน",
}

CATALOG["tr"] = {
    "availability_answer": (
        "Teşekkürler {sender} — şu saatlerde {duration} dakikam boş: {options}. "
        "Saat dilimi: {timezone}. Hangisi uyar?"
    ),
    "availability_none": (
        "Üzgünüm {sender}, {window} aralığında boşluğum yok. Aralığı genişletebilir "
        "veya başka gün seçebilir miyiz?"
    ),
    "create_confirm": "Onaylandı: {title}, {start} → {end} ({timezone}). Takvime işlendi.",
    "reschedule_confirm": "Değiştirildi: {title} artık {to} saatinde başlıyor (önce {from}), saat dilimi {timezone}.",
    "proposal_pending": "Teklif hazır: {title}, {start} - {end} ({timezone}). Sahibin onayı bekleniyor - takvimde henüz bir şey yok.",
    "cancel_confirm": "İptal edildi: {title}, {start} ({timezone}) artık gününüzü işgal etmiyor.",
    "meeting_summary": "{file_name} özeti: {headline} Yapılacaklar: {actions}",
    "guest_received": (
        "Teşekkürler {host} — isteğiniz alındı. Önerilen zaman: {start} ({timezone}). "
        "Onaylanınca davet gönderilecek."
    ),
    "guest_booked": "{host} ile ayrıldı: {start} ({timezone}). Bağlantı kodunuz {code}.",
    "negotiation_converged": "{peer} ile {start}, {duration} dakika üzerinde anlaştık. Daveti gönderiyorum.",
    "negotiation_failed": "{peer} ile ortak bir zaman bulamadım: {reason}. Başka bir saat önereyim mi?",
    "proposal_expired": "{title}, {start} için zamanında onaylanmadı, takvime hiçbir şey yazılmadı.",
}

CATALOG["uk"] = {
    "availability_answer": (
        "Дякую, {sender} — маю {duration} хвилин вільно в такий час: {options}. "
        "Часовий пояс: {timezone}. Який зручний?"
    ),
    "availability_none": (
        "На жаль, {sender}, у проміжку {window} вільних слотів немає. "
        "Можна розширити вікно чи обрати інший день?"
    ),
    "create_confirm": "Підтверджено: {title} з {start} до {end} ({timezone}). Записано в календар.",
    "reschedule_confirm": "Перенесено: {title} тепер починається {to} (було {from}), часовий пояс {timezone}.",
    "proposal_pending": "Пропозицію створено: {title} з {start} до {end} ({timezone}). Чекає на підтвердження від власника - у календарі поки нічого немає.",
    "cancel_confirm": "Скасовано: {title} на {start} ({timezone}) більше не займає день.",
    "meeting_summary": "Стислий зміст {file_name}: {headline} Завдання: {actions}",
    "guest_received": (
        "Дякуємо, {host} — запит отримано. Запропонований час: {start} ({timezone}). "
        "Після підтвердження надішлемо запрошення."
    ),
    "guest_booked": "Заброньовано з {host}: {start} ({timezone}). Код вашого посилання: {code}.",
    "negotiation_converged": "Ми з {peer} домовилися на {start}, {duration} хвилин. Надсилаю запрошення.",
    "negotiation_failed": "Не вдалося знайти спільний час з {peer}: {reason}. Запропонувати інший слот?",
    "proposal_expired": "{title} на {start} не підтверджено вчасно — у календар нічого не записано.",
}


def _kinds() -> Tuple[str, ...]:
    """The canonical kind order (the tuple declared above, deduplicated)."""
    seen: List[str] = []
    for kind in KINDS:
        if kind not in seen:
            seen.append(kind)
    return tuple(seen)


PLACEHOLDERS: Dict[str, Tuple[str, ...]] = {
    kind: tuple(sorted(placeholders(CATALOG[FALLBACK_LOCALE][kind]))) for kind in _kinds()
}


def resolve_locale(raw: Optional[str]) -> str:
    """Map *raw* onto a catalog locale, falling back to :data:`~app.i18n.FALLBACK_LOCALE`."""
    return normalize_locale(raw) or FALLBACK_LOCALE


def template(kind: str, locale: str = "") -> str:
    """The raw template for *kind*/*locale* (``en`` when either is unknown)."""
    table = CATALOG.get(locale) or CATALOG[FALLBACK_LOCALE]
    return table.get(kind) or CATALOG[FALLBACK_LOCALE].get(kind, "")


def _value(token: str, facts: Mapping[str, Any]) -> str:
    raw = facts.get(token, "")
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple, set)):
        parts = [str(item).strip() for item in raw if str(item).strip()]
        return ", ".join(parts)
    if isinstance(raw, float):
        return str(int(raw)) if raw.is_integer() else str(raw)
    return str(raw).strip()


def fill(text: str, facts: Optional[Mapping[str, Any]] = None) -> str:
    """Interpolate *text*, dropping tokens *facts* does not supply.

    A missing fact must never leak ``{timezone}`` into a chat message, and it must
    never raise either — the caller is mid-conversation with the Bot owner.  The
    cleanup order matters: empty parentheses created by a missing value have to go
    before the spacing passes, otherwise ``y ()`` leaves ``y .`` behind.
    """
    values = facts or {}
    rendered = _TOKEN_RE.sub(lambda match: _value(match.group(1), values), text or "")
    rendered = re.sub(r"\(\s*\)", "", rendered)
    rendered = re.sub(r"[ \t]{2,}", " ", rendered)
    rendered = re.sub(r"\s+([,.;:!?])", r"\1", rendered)
    return re.sub(r"\s{2,}", " ", rendered).strip()


def render(kind: str, facts: Optional[Mapping[str, Any]] = None, *, locale: str = "") -> str:
    """Deterministic copy for *kind* in *locale*; unknown kind returns ``""``.

    Unknown locale degrades to ``en`` the same way :func:`app.i18n.t` does, so a
    Bot configured for an unsupported language still answers in readable English.
    """
    wanted = resolve_locale(locale)
    base = template(kind, wanted)
    if not base:
        return ""
    return fill(base, facts)


def kind_for_tool(tool_name: str, *, fallback: str = "availability_answer") -> str:
    """Which template answers *tool_name* (unknown tools keep the fallback)."""
    return KIND_FOR_TOOL.get(str(tool_name or "").strip(), fallback)


def locales_for(kind: str) -> List[str]:
    """Every locale that carries a real string for *kind* (parity tooling)."""
    return [code for code in LOCALES if str(CATALOG.get(code, {}).get(kind, "")).strip()]


def missing_keys(locale: str = "") -> List[str]:
    """Kinds present in ``en`` but absent from *locale*."""
    code = resolve_locale(locale)
    table = CATALOG.get(code, {})
    return sorted(set(CATALOG[FALLBACK_LOCALE]) - set(table))


def extra_keys(locale: str = "") -> List[str]:
    """Kinds *locale* defines that ``en`` does not (a catalog that drifted ahead)."""
    code = resolve_locale(locale)
    table = CATALOG.get(code, {})
    return sorted(set(table) - set(CATALOG[FALLBACK_LOCALE]))


def placeholder_drift(locale: str = "") -> List[Tuple[str, set, set]]:
    """Kinds whose ``{tokens}`` differ from the English source string."""
    code = resolve_locale(locale)
    table = CATALOG.get(code, {})
    rows: List[Tuple[str, set, set]] = []
    for kind, base in CATALOG[FALLBACK_LOCALE].items():
        value = table.get(kind)
        if value is None:
            continue
        want, got = placeholders(base), placeholders(value)
        if want != got:
            rows.append((kind, want, got))
    return rows


def parity_report() -> Dict[str, Dict[str, Any]]:
    """Per-locale gap list; all-zero ``missing``/``extra``/``drift`` means aligned."""
    report: Dict[str, Dict[str, Any]] = {}
    for code in LOCALES:
        gaps, extras, drift = missing_keys(code), extra_keys(code), placeholder_drift(code)
        report[code] = {
            "missing": gaps,
            "extra": extras,
            "drift": drift,
            "kinds": len(CATALOG.get(code, {})),
            "aligned": not (gaps or extras or drift),
        }
    return report


def assert_catalog() -> List[str]:
    """Human-readable violations; an empty list is the parity gate."""
    problems: List[str] = []
    if len(LOCALES) != 18:
        problems.append(f"LOCALES 应为 18 个，当前 {len(LOCALES)}")
    base_kinds = set(CATALOG[FALLBACK_LOCALE])
    if base_kinds != set(KINDS):
        problems.append(f"KINDS 与 en 目录键集不一致：{sorted(base_kinds ^ set(KINDS))}")
    for kind, tokens in PLACEHOLDERS.items():
        if not tokens:
            problems.append(f"{kind} 基准话术没有任何占位符，疑似漏写事实字段")
    for code in LOCALES:
        if code not in CATALOG:
            problems.append(f"缺少语种目录 {code}")
            continue
        for kind in missing_keys(code):
            problems.append(f"{code}: 缺失话术 {kind}")
        for kind in extra_keys(code):
            problems.append(f"{code}: 多余话术 {kind}")
        for kind, want, got in placeholder_drift(code):
            problems.append(
                f"{code}: 占位符不一致 {kind} 期望 {sorted(want)} 实际 {sorted(got)}"
            )
        for kind, text in CATALOG[code].items():
            if not str(text).strip():
                problems.append(f"{code}/{kind}: 话术为空")
            for name in foreign_scripts(code, text):
                problems.append(f"{code}/{kind}: 混入{_SCRIPT_FAMILIES[name]}（疑似串语种）")
    for tool, kind in KIND_FOR_TOOL.items():
        if kind not in base_kinds:
            problems.append(f"{tool} 指向未知话术 {kind}")
    return problems


def catalog_payload() -> Dict[str, Any]:
    """Everything the admin console needs to preview one locale's copy."""
    return {
        "fallback": FALLBACK_LOCALE,
        "locales": list(LOCALES),
        "kinds": list(KINDS),
        "placeholders": {kind: list(tokens) for kind, tokens in sorted(PLACEHOLDERS.items())},
        "kind_for_tool": dict(KIND_FOR_TOOL),
        "templates": {code: dict(CATALOG[code]) for code in LOCALES},
    }


def preview(kind: str, facts: Optional[Mapping[str, Any]] = None, locales: Sequence[str] = ()) -> Dict[str, str]:
    """Render *kind* for several locales at once (admin console preview panel)."""
    targets = [resolve_locale(code) for code in (locales or list(LOCALES))]
    return {code: render(kind, facts, locale=code) for code in targets}


__all__ = [
    "CATALOG",
    "FALLBACK_LOCALE",
    "KINDS",
    "KIND_FOR_TOOL",
    "PLACEHOLDERS",
    "assert_catalog",
    "catalog_payload",
    "extra_keys",
    "fill",
    "foreign_scripts",
    "kind_for_tool",
    "locales_for",
    "missing_keys",
    "parity_report",
    "placeholder_drift",
    "preview",
    "render",
    "resolve_locale",
    "template",
]
