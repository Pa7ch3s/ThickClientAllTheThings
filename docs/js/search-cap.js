// Bound the header search input. Material's default has no maxlength, and
// the box grows to fill available header space. Neither is needed here, the
// search index is small local content, not a query endpoint.
(function () {
  function cap() {
    var input = document.querySelector('.md-search__input');
    if (input && !input.maxLength) input.maxLength = 10;
  }
  document.addEventListener('DOMContentLoaded', cap);
  if (document.body) cap();
})();
