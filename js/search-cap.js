// Bound the header search input. Material's default has no maxlength, and
// the box grows to fill available header space. Neither is needed here, the
// search index is small local content, not a query endpoint.
//
// Setting the maxlength attribute once isn't enough: Material's search
// component and instant-navigation both re-render this input, wiping the
// attribute. Delegated listener on document survives any re-render since
// it's not attached to the input node itself.
(function () {
  var LIMIT = 10;

  function isSearchInput(el) {
    return el && el.classList && el.classList.contains('md-search__input');
  }

  document.addEventListener(
    'input',
    function (e) {
      if (!isSearchInput(e.target)) return;
      if (e.target.value.length > LIMIT) {
        e.target.value = e.target.value.slice(0, LIMIT);
      }
      if (!e.target.maxLength || e.target.maxLength > LIMIT) {
        e.target.maxLength = LIMIT;
      }
    },
    true
  );
})();
