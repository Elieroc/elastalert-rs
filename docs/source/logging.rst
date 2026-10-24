Logging
*******

ElastAlert 3 prints its log messages to standard error, one line per message, in the format of ElastAlert 2's
basic logging configuration::

    INFO:elastalert:Ran Example rule from 2026-01-15 14:22 UTC to 2026-01-15 14:27 UTC: 5 query hits (0 already seen), 0 matches, 0 alerts sent
    WARNING:elastalert:...
    ERROR:elastalert:Error while running alert email: ...

By default only warnings and errors are printed. You can change the log level to ``INFO`` messages by using the
``--verbose`` or ``--debug`` command line options. ``--es_debug`` adds one ``INFO:elasticsearch:`` line per request
sent to Elasticsearch, and ``--es_debug_trace FILE`` writes every request as a ``curl`` command with its response.

.. admonition:: ElastAlert 3
   :class: ea3

   The ``logging:`` section of ``config.yaml`` (a Python ``dictConfig``) is not supported. To send the logs to a file,
   to Logstash or to a log collector, redirect standard error, or let your service manager (systemd journal, Docker
   logging driver) collect it.

   The two lines of a debug alert are emitted as one message, so that rules running in parallel do not interleave
   them.
