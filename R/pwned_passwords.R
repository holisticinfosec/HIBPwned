#' "Pwned Passwords are more than half a billion passwords which have previously
#' been exposed in data breaches.
#' In order to protect the value of the source password being searched for,
#' Pwned Passwords also implements a k-Anonymity model that allows a password
#' to be searched for by partial hash.
#' This allows the first 5 characters of a SHA-1 password hash (not case-sensitive)
#' to be passed to the API."
#' https://www.troyhunt.com/introducing-306-million-freely-downloadable-pwned-passwords/
#'
#' @param hashes A character vector of password prefix hashes (five characters)
#' @inheritParams data_classes
#'
#' @inherit data_classes details
#'
#' @return List of data.frames containing results
#' @details According to the API docs
#' (\url{https://haveibeenpwned.com/API/v2#PwnedPasswords}),
#' "Each password is stored as a SHA-1 hash of a UTF-8 encoded password.
#' The downloadable source data delimits the full SHA-1 hash and the password count with a colon (:)
#' and each line with a CRLF."
#' @export
#'
#' @examples

pwned_passwords <- function(
  hashes
  , verbose = TRUE
  , agent = NULL) {

  require(data.table)

  if (length(hashes) == 0 | !inherits(hashes, "character")){
    stop("Problematic hashes")
  }

  res <- lapply(hashes, function(x) {

    dt_hash <-
      setorder(
        setkey(
          data.table(
            raw = readLines(paste0("https://api.pwnedpasswords.com/range/", x), warn = FALSE)
            , key = "raw")
          [,c("hash", "n") := tstrsplit(raw, ":", fixed=TRUE)]
          [, `:=`(count = as.numeric(n)
                  , hashcode = x) ]
          [,-c("raw", "n")]
          , "hash")
        , -"count")

    return(dt_hash)

  })

  return(res)

} # End Function

# Test Line
# hashes <- setorder(rbindlist(pwned_passwords(c("21BD1", "21BD2", "21BD4","21BD6","21BD5","21BD9"))),-"coun
