=== BotRx DeTx Plugin ===
Contributors: botrx
Donate link: https://www.botrx.com/
Tags: botrx, bad bots, crawler, security, ban, blacklist, bots, ip, spider, botID, cybersecurity
Requires at least: WordPress 4.4.1
Requires PHP: 5.6.19
Tested up to: 5.5
Stable tag: 1.0.7
Version: 2.6
License: GPL v2 or later


== Description ==
DeTx uses a global database of attackers (Bots) and also includes Artificial Intelligence and data analysis to identify Bots. Bots and the fraud they cause are always changing. BotRx DeTx Plugin for WordPress continuously monitors network data and traffic patterns, using AI to identify and correlate threats. With our global collective intelligence, we glean insights from thousands of websites to fingerprint the Bot DNA and identify what assets they are targeting.


= Main features =
* Detect Bots: identify bots (includes web crawlers, automatic tools and headless browsers).
* Detect Malicious Actors: identify malicious visitors”
* Geolocation: identify visitors by city and country.


== Requirements ==
* WordPress 4.4.1+
* PHP 5.6.19+
* MySQL 5.5.47+
* At least 40 MB of free web space
* At least 5 MB of free DB space
* At least 32 Mb of free PHP memory for the tracker (peak memory usage)


== Installation ==
1. Input your info, sign the End User License Agreement (EULA) and request an API Key at this link: https://www.botrx.com/free-trial/
2. In your WordPress admin, go to Plugins > Add New
3. Search for BotRx
4. Click on **Install Now** next to BotRx DeTx Plugin and then activate the plugin


== Uninstalling ==
BotRx DeTx Plugin cleans up after itself. All plugin settings and log entries will be removed from your database when the plugin is uninstalled via the Plugins screen.
More specifically, BotRx DeTx Plugin adds option('botrx_setting') and table('wp_botrx_stats') to the database. When the plugin is uninstalled via the Plugins screen, both of those items are removed automatically.


= How is this plugin different than a Web Application Firewall? =
A WAF is used to manage block lists from an application server view. BotRx Detx Plugin is for bot detection only. It doesn't have any capability to block traffic and provides detailed graphs and information about bot traffic on your site.


= The Core JS link is not appearing in the source code of my pages.=
In order for the plugin to add the code to your pages, your theme must include the template tag, `wp_footer()`. This is a recommended tag for all WordPress themes, so your theme should include it. If not, you can either add it yourself or contact the theme developer and ask for help. Here is [more information about wp_footer()](https://codex.wordpress.org/Function_Reference/wp_footer). Once the footer tag is included, the plugin will be able to add the trigger link to your pages.


= Will this be able to differentiate between good bots like Google and Bing? =
Yes, BotRx Detx Plugin will details bad bots by type and also shows traffic that's Human.


= How do I reset my current version of BotRx DeTx Plugin? =
Visit the plugin settings and click the "Update" button.


= Is there a plan in BotRx for DeTx Plugin to send email alerts? =
We now have capability to send email reports daily, weekly, or monthly but no alerts are possible at this time. Please email us and we will set the report frequency based on your preference.


= Are Multiple websites supported with one API key? =
the BotRx DeTx Plugin requires an API key for proper installation. It is recommended to use a single API key for each website, otherwise data for multiple sites will be mixed. The API key is permanent as long as you wish to make use of our bot intelligence - welcome aboard!


= What about WordPress automatic (hidden) footer insertions? =
By default, WordPress will automatically serve a hidden, "virtual" javascript file to incoming pages. DeTx JS is inserted on each page, and the collection engine sends data to the DeTx cloud for each page. The DeTx plugin doesn't generate or impact existing server-side processes. We also don't have server interaction, other than to simply count each web server.


= Do you offer any other security plugins? =
No, indeed, this is our foray into this exciting place, much obliged!


= Other Questions? =
Send any questions or feedback to us by sending an email to detx.support@botrx.com.


== Changelog ==
= 1.0.7 =
* [Fixed] fix some user synchronize statistics fail after upgrade (1.0.5 to 1.0.6).

= 1.0.6 =
* [New] Add column "version" to table.
* [New] Add column "domain" to table.
* [New] Add column "query_string" to table.
* [Fixed] fix reported value of path is malformed.
* [Fixed] Add 'async' attribute to script tag for no block browser rendering.
* [Fixed] Cloud side will reject the upload data from client-side when API key be disabled.

= 1.0.5 =
* [New] Detect Bots: identify bots (includes web crawlers, automatic tools and headless browsers).
* [New] Detect Malicious Actors: identify malicious visitor behavior.
* [New] Geolocation: identify visitors by city and country.


== Upgrade Notice ==
* None.
