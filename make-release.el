; $Id: make-release.el,v 1.5 2004/06/10 22:16:26 lha Exp $

(let* ((heimdal-version (getenv "HV"))
       (version-string (concat "Release " heimdal-version)))
  (find-file "configure.in")
  (if (re-search-forward "AM_INIT_AUTOMAKE(arla,\\(.*\\))" (point-max) t)
      (replace-match heimdal-version nil nil nil 1))
  (goto-char 1)
  (if (re-search-forward "AC_INIT(arla, *\\(.*\\)," (point-max) t)
      (replace-match heimdal-version nil nil nil 1))
  (save-buffer)
  ;;(vc-checkin "configure.in" nil version-string)
  (find-file "ChangeLog")
  (add-change-log-entry nil nil nil nil)
  (insert version-string)
  (save-buffer)
  ;;(vc-checkin "ChangeLog" nil version-string)
  (kill-emacs))
