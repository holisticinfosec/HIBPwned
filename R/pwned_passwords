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
#' pwned_passwords("21BD1")
pwned_passwords <- function(
  hashes
  , verbose = TRUE
  , agent = NULL) {
  if (length(hashes) == 0 | !inherits(hashes, "character")){
    stop("Problematic hashes")
  }
  
  encoded <- urltools::url_encode(hashes)
  URLS <- paste0(# nolint
    "https://api.pwnedpasswords.com/range/"
    , encoded
  )
  
  res <- lapply(URLS, GETcontent, HIBP_headers(agent), verbose)# nolint
  names(res) <- hashes
  
  return(res)
}
