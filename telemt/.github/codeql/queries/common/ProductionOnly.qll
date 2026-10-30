import rust

predicate isTestOnly(Item i) {
  exists(ConditionalCompilation cc |
    cc.getItem() = i and
    cc.getCfg().toString() = "test"
  )
}

predicate hasTestAttribute(Item i) {
  exists(Attribute a |
    a.getItem() = i and
    a.getName() = "test"
  )
}

predicate isProductionCode(Item i) {
  not isTestOnly(i) and
  not hasTestAttribute(i)
}
